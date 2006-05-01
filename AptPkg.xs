/* $Id$ */

/*
 * perl interface to libapt-pkg
 */

#include <string>
#include <vector>
#include <apt-pkg/init.h>
#include <apt-pkg/error.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/cmndline.h>
#include <apt-pkg/progress.h>
#include <apt-pkg/pkgsystem.h>
#include <apt-pkg/sourcelist.h>
#include <apt-pkg/version.h>
#include <apt-pkg/cachefile.h>
#include <apt-pkg/pkgrecords.h>
#include <apt-pkg/srcrecords.h>

#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "utils.h"

/* XS has grief with colons */
#define Configuration_Item	    Configuration::Item
#define pkgSrcRecords_Parser	    pkgSrcRecords::Parser

/* ensure parent SV persists for the life of the child */
template <class T, class A> class parented : public T {
public:
    SV *parent_sv;

    inline parented(SV* p, A &a) : T(a) {
	dTHX;
	parent_sv = SvREFCNT_inc(p);
    };

    inline ~parented() {
	dTHX;
	SvREFCNT_dec(parent_sv);
    };
};

#define THIS_sv			    ST(0)
#define pkgRecords_p		    parented<pkgRecords, pkgCache>
#define pkgCache_PkgIterator_p	    parented<pkgCache::PkgIterator, pkgCache::PkgIterator>
#define pkgCache_PkgFileIterator_p  parented<pkgCache::PkgFileIterator, pkgCache::PkgFileIterator>
#define pkgCache_VerIterator_p	    parented<pkgCache::VerIterator, pkgCache::VerIterator>
#define pkgCache_DepIterator_p	    parented<pkgCache::DepIterator, pkgCache::DepIterator>
#define pkgCache_PrvIterator_p	    parented<pkgCache::PrvIterator, pkgCache::PrvIterator>
#define pkgCache_VerFileIterator_p  parented<pkgCache::VerFileIterator, pkgCache::VerFileIterator>

/* handle warnings/errors */
static void handle_errors(int fatal)
{
    while (!_error->empty())
    {
	string msg;
	if (_error->PopMessage(msg) && fatal)
	    croak("%s\n", msg.c_str());
	else
	    warn("%s\n", msg.c_str());
    }
}

/* convert strings to CommandLine::Flags */
static int cmdline_flag(char const *f)
{
    if (strEQ(f, "HasArg") || strEQ(f, "has_arg"))
	return CommandLine::HasArg;

    if (strEQ(f, "IntLevel") || strEQ(f, "int_level"))
	return CommandLine::IntLevel;

    if (strEQ(f, "Boolean") || strEQ(f, "boolean"))
	return CommandLine::Boolean;

    if (strEQ(f, "InvBoolean") || strEQ(f, "inv_boolean"))
	return CommandLine::InvBoolean;

    if (strEQ(f, "ConfigFile") || strEQ(f, "config_file"))
	return CommandLine::ConfigFile;

    if (strEQ(f, "ArbItem") || strEQ(f, "arb_item"))
	return CommandLine::ArbItem;

    warn("unrecognised command line option type `%s'", f);
    return 0;
}

/* automagically do _config and _system initialisation if required */
static int init_done = 0;

#define INIT_CONFIG 1
#define INIT_SYSTEM 2

static void auto_init(pTHX_ int required)
{
    if (!(init_done & INIT_CONFIG))
    {
	load_module(PERL_LOADMOD_NOIMPORT, newSVpvn("AptPkg::Config", 14), 0);
	eval_pv("$AptPkg::Config::_config->init;"
		"$AptPkg::Config::_config->{quiet} = 2;", 1);
    }

    if ((required & INIT_SYSTEM) && !(init_done & INIT_SYSTEM))
    {
	load_module(PERL_LOADMOD_NOIMPORT, newSVpvn("AptPkg::System", 14), 0);
	eval_pv("$AptPkg::System::_system = $AptPkg::Config::_config->system;",
	    1);
    }
}

/* assigning to the $AptPkg::System::_system needs to magically modify
   the global _system (ick) */
static int _system_set(pTHX_ SV *sv, MAGIC *mg)
{
    if (SvROK(sv) && sv_derived_from(sv, "AptPkg::System"))
    {
	init_done |= INIT_SYSTEM;
	_system = (pkgSystem *) SvIV((SV *) SvRV(sv));
    }
    else
	croak("can't set _system to a value not of type AptPkg::System");

    return 1;
}

static MGVTBL _system_magic = {
    0, _system_set, 0, 0, 0
};

/* for AptPkg::Dep, AptPkg::State and AptPkg::Flag constants */
XS(XS_AptPkg__constant)
{
    dXSARGS;
    ST(0) = newSViv(CvXSUBANY(cv).any_iv);
    sv_2mortal(ST(0));
    XSRETURN(1);
}

#define CONSTANT(sub, enum) \
    cv = newXS(sub, XS_AptPkg__constant, file); \
    CvXSUBANY(cv).any_iv = enum

MODULE = AptPkg  PACKAGE = AptPkg

PROTOTYPES: DISABLE

bool
_init_config(conf)
    Configuration *conf
  CODE:
    if (conf == _config)
    	init_done |= INIT_CONFIG;

    if (!(RETVAL = pkgInitConfig(*conf)))
	handle_errors(0);

  OUTPUT:
    RETVAL

pkgSystem *
_init_system(conf)
    Configuration *conf
  CODE:
    pkgSystem *sys = 0;
    if (!pkgInitSystem(*conf, sys))
	handle_errors(0);

    RETVAL = sys;

  OUTPUT:
    RETVAL

void
_parse_cmdline(conf, args, ...)
    Configuration *conf
    SV *args
  PPCODE:
    if (!(SvROK(args) && SvTYPE(SvRV(args)) == SVt_PVAV))
	croak("AptPkg::_parse_cmdline: array reference required");

    AV *av = (AV *) SvRV(args);
    I32 len = av_len(av) + 1;

    if (len && items > 2)
    {
	CommandLine::Args *a = new CommandLine::Args[len + 1];
	I32 j = 0;
	for (I32 i = 0; i < len; i++)
	{
	    char const *type = 0;
	    char const *e;
	    if ((e = parse_avref(aTHX_ av_fetch(av, i, 0), "czs|s",
				 &a[j].ShortOpt, &a[j].LongOpt,
				 &a[j].ConfName, &type)))
		warn("AptPkg::_parse_cmdline: invalid array %d (%s)", i, e);
	    else
		a[j++].Flags = type ? cmdline_flag(type) : 0;
	}

	a[j].ShortOpt = 0;
	a[j].LongOpt = 0;

	CommandLine cmd(a, conf);

	int argc = items - 1;
	char const **argv = new char const*[argc];

	j = 0;
	argv[j++] = PL_origfilename;
	for (I32 i = 2; i < items; i++)
	    argv[j++] = SvPV_nolen(ST(i));

	if (cmd.Parse(argc, argv))
	    for (I32 i = 0; cmd.FileList[i]; i++)
		XPUSHs(sv_2mortal(newSVpv(cmd.FileList[i], 0)));

	delete [] a;
	delete [] argv;
	handle_errors(1);
    }

MODULE = AptPkg  PACKAGE = AptPkg::_config

BOOT:
    /* make global available */
    sv_setref_pv(get_sv("AptPkg::_config::_config", 1), "AptPkg::_config",
		 (void *) _config);

Configuration *
Configuration::new()

void
Configuration::DESTROY()
  INIT:
    if (THIS == _config)
	XSRETURN_EMPTY;

string
Configuration::Find(name, default_value = 0)
    char *name
    char *default_value

string
Configuration::FindFile(name, default_value = 0)
    char *name
    char *default_value

string
Configuration::FindDir(name, default_value = 0)
    char *name
    char *default_value

bool
Configuration::FindB(name, default_value = 0)
    char *name
    int default_value

string
Configuration::FindAny(name, default_value = 0)
    char *name
    char *default_value

string
Configuration::Set(name, value)
    char *name
    string value
  CODE:
    THIS->Set(name, value);
    RETVAL = value;

  OUTPUT:
    RETVAL

bool
Configuration::Exists(name)
    char *name

bool
Configuration::ExistsAny(name)
    char *name

Configuration_Item const *
Configuration::Tree(name = 0)
    char *name

void
Configuration::Dump()

bool
ReadConfigFile(config, file, as_sectional = false, depth = 0)
    Configuration *config
    string file
    bool as_sectional
    int depth
  C_ARGS:
    *config, file, as_sectional, depth

  POSTCALL:
    handle_errors(0);

bool
ReadConfigDir(config, dir, as_sectional = false, depth = 0)
    Configuration *config
    string dir
    bool as_sectional
    int depth
  C_ARGS:
    *config, dir, as_sectional, depth

  POSTCALL:
    handle_errors(0);

MODULE = AptPkg  PACKAGE = AptPkg::Config::_item

string
Configuration_Item::Value()
  CODE:
    RETVAL = THIS->Value;

  OUTPUT:
    RETVAL

string
Configuration_Item::Tag()
  CODE:
    RETVAL = THIS->Tag;

  OUTPUT:
    RETVAL

string
Configuration_Item::FullTag(stop = 0)
    Configuration_Item const *stop

Configuration_Item const *
Configuration_Item::Parent()
  CODE:
    RETVAL = THIS->Parent;

  OUTPUT:
    RETVAL

Configuration_Item const *
Configuration_Item::Child()
  CODE:
    RETVAL = THIS->Child;

  OUTPUT:
    RETVAL

Configuration_Item const *
Configuration_Item::Next()
  CODE:
    RETVAL = THIS->Next;

  OUTPUT:
    RETVAL

MODULE = AptPkg  PACKAGE = AptPkg::System

BOOT:
    {
	/* make global available */
	SV *sv = sv_setref_pv(get_sv("AptPkg::System::_system", 1),
			      "AptPkg::System", (void *) _system);

	/* and make it magical, so that setting the value of $_system
	   modifies the underlying _system global */
	sv_magic(sv, 0, '~', 0, 0);
	mg_find(sv, '~')->mg_virtual = &_system_magic;
	SvMAGICAL_on(sv);
    }

char *
pkgSystem::Label()
  CODE:
    RETVAL = (char *) THIS->Label;

  OUTPUT:
    RETVAL

pkgVersioningSystem *
pkgSystem::VS()
  CODE:
    RETVAL = THIS->VS;

  OUTPUT:
    RETVAL

bool
pkgSystem::Lock()
  POSTCALL:
    handle_errors(0);

bool
pkgSystem::UnLock(NoErrors = false)
    bool NoErrors
  POSTCALL:
    handle_errors(0);

MODULE = AptPkg  PACKAGE = AptPkg::Version

char *
pkgVersioningSystem::Label()
  CODE:
    RETVAL = (char *) THIS->Label;

  OUTPUT:
    RETVAL

int
pkgVersioningSystem::CmpVersion(a, b)
    char *a
    char *b

int
pkgVersioningSystem::CmpReleaseVer(a, b)
    char *a
    char *b

bool
pkgVersioningSystem::CheckDep(pkg, op, dep)
    char *pkg
    unsigned op
    char *dep

string
pkgVersioningSystem::UpstreamVersion(str)
    char *str

MODULE = AptPkg  PACKAGE = AptPkg::_cache

pkgCacheFile *
pkgCacheFile::new()
  PREINIT:
    auto_init(aTHX_ INIT_CONFIG|INIT_SYSTEM);

void
pkgCacheFile::DESTROY()

bool
pkgCacheFile::Open(lock = false)
    bool lock
  PREINIT:
    OpTextProgress progress(*_config);

  C_ARGS:
    progress, lock

  POSTCALL:
    handle_errors(0);

void
pkgCacheFile::Close()

pkgCache_PkgIterator_p *
pkgCacheFile::FindPkg(name)
    string name
  CODE:
    pkgCache *cache = *THIS;
    pkgCache::PkgIterator p = cache->FindPkg(name);
    if (p.end())
	XSRETURN_UNDEF;

    RETVAL = new pkgCache_PkgIterator_p(THIS_sv, p);

  OUTPUT:
    RETVAL

pkgCache_PkgIterator_p *
pkgCacheFile::PkgBegin()
  CODE:
    pkgCache *cache = *THIS;
    pkgCache::PkgIterator p = cache->PkgBegin();
    if (p.end())
	XSRETURN_UNDEF;

    RETVAL = new pkgCache_PkgIterator_p(THIS_sv, p);

  OUTPUT:
    RETVAL

SV *
pkgCacheFile::FileList()
  PPCODE:
    pkgCache *cache = *THIS;
    for (pkgCache::PkgFileIterator i = cache->FileBegin(); !i.end(); i++)
    {
	pkgCache_PkgFileIterator_p *f = new pkgCache_PkgFileIterator_p(THIS_sv, i);
	SV *file = sv_newmortal();
	sv_setref_pv(file, "AptPkg::Cache::_pkg_file", (void *) f);
	XPUSHs(file);
    }

SV *
pkgCacheFile::Packages()
  CODE:
    pkgCache *cache = *THIS;
    pkgRecords_p *r = new pkgRecords_p(THIS_sv, *cache);
    RETVAL = sv_setref_pv(NEWSV(0, 0), "AptPkg::_pkg_records", (void *) r);

  OUTPUT:
    RETVAL

MODULE = AptPkg  PACKAGE = AptPkg::Cache::_package

void
pkgCache_PkgIterator_p::DESTROY()

int
pkgCache_PkgIterator_p::Next()
  CODE:
    (*THIS)++;
    RETVAL = !THIS->end();

  OUTPUT:
    RETVAL

char *
pkgCache_PkgIterator_p::Name()
  CODE:
    RETVAL = (char *) THIS->Name();

  OUTPUT:
    RETVAL

char *
pkgCache_PkgIterator_p::Section()
  CODE:
    RETVAL = (char *) THIS->Section();

  OUTPUT:
    RETVAL

SV *
pkgCache_PkgIterator_p::VersionList()
  PPCODE:
    for (pkgCache::VerIterator i = THIS->VersionList(); !i.end(); i++)
    {
	pkgCache_VerIterator_p *v = new pkgCache_VerIterator_p(THIS_sv, i);
	SV *ver = sv_newmortal();
	sv_setref_pv(ver, "AptPkg::Cache::_version", (void *) v);
	XPUSHs(ver);
    }

SV *
pkgCache_PkgIterator_p::CurrentVer()
  CODE:
    if (!(*THIS)->CurrentVer)
	XSRETURN_UNDEF;

    pkgCache::VerIterator i = THIS->CurrentVer();
    pkgCache_VerIterator_p *v = new pkgCache_VerIterator_p(THIS_sv, i);
    RETVAL = sv_setref_pv(NEWSV(0, 0), "AptPkg::Cache::_version", (void *) v);

  OUTPUT:
    RETVAL

SV *
pkgCache_PkgIterator_p::RevDependsList()
  PPCODE:
    for (pkgCache::DepIterator i = THIS->RevDependsList(); !i.end(); i++)
    {
	pkgCache_DepIterator_p *d = new pkgCache_DepIterator_p(THIS_sv, i);
	SV *dep = sv_newmortal();
	sv_setref_pv(dep, "AptPkg::Cache::_depends", (void *) d);
	XPUSHs(dep);
    }

SV *
pkgCache_PkgIterator_p::ProvidesList()
  PPCODE:
    for (pkgCache::PrvIterator i = THIS->ProvidesList(); !i.end(); i++)
    {
	pkgCache_PrvIterator_p *p = new pkgCache_PrvIterator_p(THIS_sv, i);
	SV *prv = sv_newmortal();
	sv_setref_pv(prv, "AptPkg::Cache::_provides", (void *) p);
	XPUSHs(prv);
    }

unsigned long
pkgCache_PkgIterator_p::Index()

SV *
pkgCache_PkgIterator_p::SelectedState()
  PREINIT:
    char *rv;

  CODE:
    switch ((*THIS)->SelectedState)
    {
    case pkgCache::State::Unknown:	    rv = "Unknown";		break;
    case pkgCache::State::Install:	    rv = "Install";		break;
    case pkgCache::State::Hold:		    rv = "Hold";		break;
    case pkgCache::State::DeInstall:	    rv = "DeInstall";		break;
    case pkgCache::State::Purge:	    rv = "Purge";		break;
    default:				    XSRETURN_UNDEF;
    }

    RETVAL = newSViv((*THIS)->SelectedState);
    sv_setpv(RETVAL, rv);
    SvIOK_on(RETVAL);

  OUTPUT:
    RETVAL

SV *
pkgCache_PkgIterator_p::InstState()
  PREINIT:
    char *rv;

  CODE:
    switch ((*THIS)->InstState)
    {
    case pkgCache::State::Ok:		    rv = "Ok";			break;
    case pkgCache::State::ReInstReq:	    rv = "ReInstReq";		break;
    case pkgCache::State::HoldInst:	    rv = "HoldInst";		break;
    case pkgCache::State::HoldReInstReq:    rv = "HoldReInstReq";	break;
    default:				    XSRETURN_UNDEF;
    }

    RETVAL = newSViv((*THIS)->InstState);
    sv_setpv(RETVAL, rv);
    SvIOK_on(RETVAL);

  OUTPUT:
    RETVAL

SV *
pkgCache_PkgIterator_p::CurrentState()
  PREINIT:
    char *rv;

  CODE:
    switch ((*THIS)->CurrentState)
    {
    case pkgCache::State::NotInstalled:	    rv = "NotInstalled";	break;
    case pkgCache::State::UnPacked:	    rv = "UnPacked";		break;
    case pkgCache::State::HalfConfigured:   rv = "HalfConfigured";	break;
    case pkgCache::State::HalfInstalled:    rv = "HalfInstalled";	break;
    case pkgCache::State::ConfigFiles:	    rv = "ConfigFiles";		break;
    case pkgCache::State::Installed:	    rv = "Installed";		break;
    default:				    XSRETURN_UNDEF;
    }

    RETVAL = newSViv((*THIS)->CurrentState);
    sv_setpv(RETVAL, rv);
    SvIOK_on(RETVAL);

  OUTPUT:
    RETVAL

SV *
pkgCache_PkgIterator_p::Flags()
  CODE:
    string flags = "";
    if ((*THIS)->Flags & pkgCache::Flag::Auto)
	flags += "Auto";

    if ((*THIS)->Flags & pkgCache::Flag::Essential)
    {
	if (flags.size()) flags += ",";
	flags += "Essential";
    }

    if ((*THIS)->Flags & pkgCache::Flag::Important)
    {
	if (flags.size()) flags += ",";
	flags += "Important";
    }

    RETVAL = newSViv((*THIS)->Flags);
    sv_setpv(RETVAL, (char *) flags.c_str());
    SvIOK_on(RETVAL);

  OUTPUT:
    RETVAL

MODULE = AptPkg  PACKAGE = AptPkg::Cache::_version

void
pkgCache_VerIterator_p::DESTROY()

char *
pkgCache_VerIterator_p::VerStr()
  CODE:
    RETVAL = (char *) THIS->VerStr();

  OUTPUT:
    RETVAL

char *
pkgCache_VerIterator_p::Section()
  CODE:
    RETVAL = (char *) THIS->Section();

  OUTPUT:
    RETVAL

char *
pkgCache_VerIterator_p::Arch()
  CODE:
    RETVAL = (char *) THIS->Arch();

  OUTPUT:
    RETVAL

SV *
pkgCache_VerIterator_p::ParentPkg()
  CODE:
    pkgCache::PkgIterator i = THIS->ParentPkg();
    pkgCache_PkgIterator_p *p = new pkgCache_PkgIterator_p(THIS_sv, i);
    RETVAL = sv_setref_pv(NEWSV(0, 0), "AptPkg::Cache::_package", (void *) p);

  OUTPUT:
    RETVAL

SV *
pkgCache_VerIterator_p::DependsList()
  PPCODE:
    for (pkgCache::DepIterator i = THIS->DependsList(); !i.end(); i++)
    {
	pkgCache_DepIterator_p *d = new pkgCache_DepIterator_p(THIS_sv, i);
	SV *dep = sv_newmortal();
	sv_setref_pv(dep, "AptPkg::Cache::_depends", (void *) d);
	XPUSHs(dep);
    }

SV *
pkgCache_VerIterator_p::ProvidesList()
  PPCODE:
    for (pkgCache::PrvIterator i = THIS->ProvidesList(); !i.end(); i++)
    {
	pkgCache_PrvIterator_p *p = new pkgCache_PrvIterator_p(THIS_sv, i);
	SV *prv = sv_newmortal();
	sv_setref_pv(prv, "AptPkg::Cache::_provides", (void *) p);
	XPUSHs(prv);
    }

SV *
pkgCache_VerIterator_p::FileList()
  PPCODE:
    for (pkgCache::VerFileIterator i = THIS->FileList(); !i.end(); i++)
    {
	pkgCache_VerFileIterator_p *f = new pkgCache_VerFileIterator_p(THIS_sv, i);
	SV *file = sv_newmortal();
	sv_setref_pv(file, "AptPkg::Cache::_ver_file", (void *) f);
	XPUSHs(file);
    }

unsigned long
pkgCache_VerIterator_p::Index()

SV *
pkgCache_VerIterator_p::Priority()
  CODE:
    char const *p = THIS->PriorityType();
    RETVAL = newSViv((*THIS)->Priority);
    sv_setpv(RETVAL, (char *) p);
    SvIOK_on(RETVAL);

  OUTPUT:
    RETVAL

MODULE = AptPkg  PACKAGE = AptPkg::Cache::_depends

void
pkgCache_DepIterator_p::DESTROY()

char *
pkgCache_DepIterator_p::TargetVer()
  CODE:
    RETVAL = (char *) THIS->TargetVer();

  OUTPUT:
    RETVAL

SV *
pkgCache_DepIterator_p::TargetPkg()
  CODE:
    pkgCache::PkgIterator i = THIS->TargetPkg();
    pkgCache_PkgIterator_p *p = new pkgCache_PkgIterator_p(THIS_sv, i);
    RETVAL = sv_setref_pv(NEWSV(0, 0), "AptPkg::Cache::_package", (void *) p);

  OUTPUT:
    RETVAL

SV *
pkgCache_DepIterator_p::ParentVer()
  CODE:
    pkgCache::VerIterator i = THIS->ParentVer();
    pkgCache_VerIterator_p *v = new pkgCache_VerIterator_p(THIS_sv, i);
    RETVAL = sv_setref_pv(NEWSV(0, 0), "AptPkg::Cache::_version", (void *) v);

  OUTPUT:
    RETVAL

SV *
pkgCache_DepIterator_p::ParentPkg()
  CODE:
    pkgCache::PkgIterator i = THIS->ParentPkg();
    pkgCache_PkgIterator_p *p = new pkgCache_PkgIterator_p(THIS_sv, i);
    RETVAL = sv_setref_pv(NEWSV(0, 0), "AptPkg::Cache::_package", (void *) p);

  OUTPUT:
    RETVAL

unsigned long
pkgCache_DepIterator_p::Index()

SV *
pkgCache_DepIterator_p::CompType()
  CODE:
    RETVAL = newSViv((*THIS)->CompareOp);
    sv_setpv(RETVAL, (char *) THIS->CompType());
    SvIOK_on(RETVAL);

  OUTPUT:
    RETVAL

SV *
pkgCache_DepIterator_p::CompTypeDeb()
  CODE:
    RETVAL = newSViv((*THIS)->CompareOp);
    sv_setpv(RETVAL, (char *) THIS->Cache()->CompTypeDeb((*THIS)->CompareOp));
    SvIOK_on(RETVAL);

  OUTPUT:
    RETVAL

SV *
pkgCache_DepIterator_p::DepType()
  CODE:
    RETVAL = newSViv((*THIS)->Type);
    sv_setpv(RETVAL, (char *) THIS->DepType());
    SvIOK_on(RETVAL);

  OUTPUT:
    RETVAL

MODULE = AptPkg  PACKAGE = AptPkg::Cache::_provides

void
pkgCache_PrvIterator_p::DESTROY()

char *
pkgCache_PrvIterator_p::Name()
  CODE:
    RETVAL = (char *) THIS->Name();

  OUTPUT:
    RETVAL

char *
pkgCache_PrvIterator_p::ProvideVersion()
  CODE:
    RETVAL = (char *) THIS->ProvideVersion();

  OUTPUT:
    RETVAL

SV *
pkgCache_PrvIterator_p::OwnerVer()
  CODE:
    pkgCache::VerIterator i = THIS->OwnerVer();
    pkgCache_VerIterator_p *v = new pkgCache_VerIterator_p(THIS_sv, i);
    RETVAL = sv_setref_pv(NEWSV(0, 0), "AptPkg::Cache::_version", (void *) v);

  OUTPUT:
    RETVAL

SV *
pkgCache_PrvIterator_p::OwnerPkg()
  CODE:
    pkgCache::PkgIterator i = THIS->OwnerPkg();
    pkgCache_PkgIterator_p *p = new pkgCache_PkgIterator_p(THIS_sv, i);
    RETVAL = sv_setref_pv(NEWSV(0, 0), "AptPkg::Cache::_package", (void *) p);

  OUTPUT:
    RETVAL

unsigned long
pkgCache_PrvIterator_p::Index()

MODULE = AptPkg  PACKAGE = AptPkg::Cache::_pkg_file

void
pkgCache_PkgFileIterator_p::DESTROY()

char *
pkgCache_PkgFileIterator_p::FileName()
  CODE:
    RETVAL = (char *) THIS->FileName();

  OUTPUT:
    RETVAL

char *
pkgCache_PkgFileIterator_p::Archive()
  CODE:
    RETVAL = (char *) THIS->Archive();

  OUTPUT:
    RETVAL

char *
pkgCache_PkgFileIterator_p::Component()
  CODE:
    RETVAL = (char *) THIS->Component();

  OUTPUT:
    RETVAL

char *
pkgCache_PkgFileIterator_p::Version()
  CODE:
    RETVAL = (char *) THIS->Version();

  OUTPUT:
    RETVAL

char *
pkgCache_PkgFileIterator_p::Origin()
  CODE:
    RETVAL = (char *) THIS->Origin();

  OUTPUT:
    RETVAL

char *
pkgCache_PkgFileIterator_p::Label()
  CODE:
    RETVAL = (char *) THIS->Label();

  OUTPUT:
    RETVAL

char *
pkgCache_PkgFileIterator_p::Site()
  CODE:
    RETVAL = (char *) THIS->Site();

  OUTPUT:
    RETVAL

char *
pkgCache_PkgFileIterator_p::Architecture()
  CODE:
    RETVAL = (char *) THIS->Architecture();

  OUTPUT:
    RETVAL

char *
pkgCache_PkgFileIterator_p::IndexType()
  CODE:
    RETVAL = (char *) THIS->IndexType();

  OUTPUT:
    RETVAL

unsigned long
pkgCache_PkgFileIterator_p::Index()

bool
pkgCache_PkgFileIterator_p::IsOk()
  CODE:
    RETVAL = (char *) THIS->IsOk();

  OUTPUT:
    RETVAL

MODULE = AptPkg  PACKAGE = AptPkg::Cache::_ver_file

void
pkgCache_VerFileIterator_p::DESTROY()

SV *
pkgCache_VerFileIterator_p::File()
  CODE:
    pkgCache::PkgFileIterator i = THIS->File();
    pkgCache_PkgFileIterator_p *p = new pkgCache_PkgFileIterator_p(THIS_sv, i);
    RETVAL = sv_setref_pv(NEWSV(0, 0), "AptPkg::Cache::_pkg_file", (void *) p);

  OUTPUT:
    RETVAL

unsigned long
pkgCache_VerFileIterator_p::Index()

off_t
pkgCache_VerFileIterator_p::Offset()
  CODE:
    RETVAL = (*THIS)->Offset;

  OUTPUT:
    RETVAL

unsigned short
pkgCache_VerFileIterator_p::Size()
  CODE:
    RETVAL = (*THIS)->Size;

  OUTPUT:
    RETVAL

MODULE = AptPkg  PACKAGE = AptPkg::_pkg_records

void
pkgRecords_p::DESTROY()

SV *
pkgRecords_p::cache()
  PPCODE:
    XPUSHs(sv_mortalcopy(THIS->parent_sv));

SV *
pkgRecords_p::Lookup(pack)
    pkgCache_VerFileIterator_p *pack
  PPCODE:
    pkgRecords::Parser &p = THIS->Lookup(*pack);

    string v;
#define PUSH_PAIR(_name_) \
    if ((v = p._name_()).size()) \
    { \
	EXTEND(SP, 2); \
	PUSHs(sv_2mortal(newSVpvn(#_name_, sizeof(#_name_)-1))); \
	PUSHs(sv_2mortal(newSVpvn(v.c_str(), v.size()))); \
    }

    PUSH_PAIR(FileName)
    PUSH_PAIR(MD5Hash)
    PUSH_PAIR(SourcePkg)
    PUSH_PAIR(Maintainer)
    PUSH_PAIR(ShortDesc)
    PUSH_PAIR(LongDesc)
    PUSH_PAIR(Name)

MODULE = AptPkg  PACKAGE = AptPkg::_pkg_source_list

pkgSourceList *
pkgSourceList::new(list = 0)
    char *list
  PREINIT:
    auto_init(aTHX_ INIT_CONFIG);

  C_ARGS:
  POSTCALL:
    if (list)
	RETVAL->Read(list);
    else
	RETVAL->ReadMainList();

    handle_errors(0);

void
pkgSourceList::DESTROY()

MODULE = AptPkg  PACKAGE = AptPkg::_pkg_src_records

pkgSrcRecords *
pkgSrcRecords::new(sources)
    pkgSourceList *sources
  C_ARGS:
    *sources

  POSTCALL:
    handle_errors(0);

void
pkgSrcRecords::DESTROY()

void
pkgSrcRecords::Restart()

SV *
pkgSrcRecords::Find(src, src_only = false)
    char *src
    bool src_only
  PPCODE:
    pkgSrcRecords::Parser *parser = THIS->Find(src, src_only);
    if (!parser)
	XSRETURN_EMPTY;

    if (GIMME_V != G_ARRAY)
    {
	XPUSHs(sv_2mortal(newSVpv(parser->Package().c_str(), 0)));
	XSRETURN(1);
    }

    {
	/* for PUSH_PAIR */
	pkgSrcRecords::Parser &p = *parser;
	string v;

	PUSH_PAIR(Package)
	PUSH_PAIR(Version)
	PUSH_PAIR(Maintainer)
	PUSH_PAIR(Section)
    }

    char const **b = parser->Binaries();
    if (b && *b)
    {
	AV *av = newAV();
	while (*b)
	    av_push(av, newSVpv(*b++, 0));

	SV *a = sv_newmortal();
	SvUPGRADE(a, SVt_RV);
	SvRV(a) = (SV *) av;
	SvROK_on(a);

	EXTEND(SP, 2);
	PUSHs(sv_2mortal(newSVpv("Binaries", 0)));
	PUSHs(a);
    }

    vector<pkgSrcRecords::Parser::BuildDepRec> bd;
    if (parser->BuildDepends(bd, false))
    {
	HV *hv = newHV();
	for (vector<pkgSrcRecords::Parser::BuildDepRec>::const_iterator b =
	    bd.begin(); b != bd.end(); b++)
	{
	    char const *key = parser->BuildDepType(b->Type);
	    STRLEN klen = strlen(key);

	    AV *dep_list;
	    if (SV **e = hv_fetch(hv, key, klen, 0))
	    {
		dep_list = (AV *) SvRV(*e);
	    }
	    else
	    {
		SV *s = newSV(0);
		SvUPGRADE(s, SVt_RV);
		SvRV(s) = (SV *) (dep_list = newAV());
		SvROK_on(s);

		hv_store(hv, key, klen, s, 0);
	    }

	    AV *dep = newAV();
	    av_push(dep, newSVpvn(b->Package.c_str(), b->Package.size()));
	    if (b->Op || !b->Version.empty())
	    {
		SV *o = newSViv(b->Op);
		sv_setpv(o, pkgCache::CompType(b->Op));
		SvIOK_on(o);
		av_push(dep, o);
	    }

	    if (!b->Version.empty())
		av_push(dep, newSVpvn(b->Version.c_str(), b->Version.size()));

	    SV *d = newSV(0);
	    SvUPGRADE(d, SVt_RV);
	    SvRV(d) = (SV *) dep;
	    SvROK_on(d);
	    av_push(dep_list, d);
	}

	SV *s = sv_newmortal();
	SvUPGRADE(s, SVt_RV);
	SvRV(s) = (SV *) hv;
	SvROK_on(s);

	EXTEND(SP, 2);
	PUSHs(sv_2mortal(newSVpv("BuildDepends", 0)));
	PUSHs(s);
    }

    vector<pkgSrcRecords::File> files;
    if (parser->Files(files))
    {
	AV *av = newAV();
	for (vector<pkgSrcRecords::File>::const_iterator f = files.begin();
	    f != files.end(); f++)
	{
	    HV *hv = newHV();

	    hv_store(hv, "MD5Hash", 7,
		newSVpvn(f->MD5Hash.c_str(), f->MD5Hash.size()), 0);

	    hv_store(hv, "Size", 4, newSVuv(f->Size), 0);
	    hv_store(hv, "ArchiveURI", 10,
		newSVpv(parser->Index().ArchiveURI(f->Path).c_str(), 0), 0);

	    hv_store(hv, "Type", 4, newSVpvn(f->Type.c_str(), f->Type.size()),
		0);

	    SV *h = newSV(0);
	    SvUPGRADE(h, SVt_RV);
	    SvRV(h) = (SV *) hv;
	    SvROK_on(h);
	    av_push(av, h);
	}

	SV *s = sv_newmortal();
	SvUPGRADE(s, SVt_RV);
	SvRV(s) = (SV *) av;
	SvROK_on(s);

	EXTEND(SP, 4);
	PUSHs(sv_2mortal(newSVpv("Files", 0)));
	PUSHs(s);
    }

MODULE = AptPkg  PACKAGE = AptPkg

BOOT:
    {
	/* constants */
        CV *cv;

	/* pkgCache::Dep::DepType */
	CONSTANT("AptPkg::Dep::Depends",	pkgCache::Dep::Depends);
	CONSTANT("AptPkg::Dep::PreDepends",	pkgCache::Dep::PreDepends);
	CONSTANT("AptPkg::Dep::Suggests",	pkgCache::Dep::Suggests);
	CONSTANT("AptPkg::Dep::Recommends",	pkgCache::Dep::Recommends);
	CONSTANT("AptPkg::Dep::Conflicts",	pkgCache::Dep::Conflicts);
	CONSTANT("AptPkg::Dep::Replaces",	pkgCache::Dep::Replaces);
	CONSTANT("AptPkg::Dep::Obsoletes",	pkgCache::Dep::Obsoletes);

	/* pkgCache::Dep::DepCompareOp */
	CONSTANT("AptPkg::Dep::Or",		pkgCache::Dep::Or);
	CONSTANT("AptPkg::Dep::NoOp",		pkgCache::Dep::NoOp);
	CONSTANT("AptPkg::Dep::LessEq",		pkgCache::Dep::LessEq);
	CONSTANT("AptPkg::Dep::GreaterEq",	pkgCache::Dep::GreaterEq);
	CONSTANT("AptPkg::Dep::Less",		pkgCache::Dep::Less);
	CONSTANT("AptPkg::Dep::Greater",	pkgCache::Dep::Greater);
	CONSTANT("AptPkg::Dep::Equals",		pkgCache::Dep::Equals);
	CONSTANT("AptPkg::Dep::NotEquals",	pkgCache::Dep::NotEquals);

	/* pkgCache::State::VerPriority */
	CONSTANT("AptPkg::State::Important",	pkgCache::State::Important);
	CONSTANT("AptPkg::State::Required",	pkgCache::State::Required);
	CONSTANT("AptPkg::State::Standard",	pkgCache::State::Standard);
	CONSTANT("AptPkg::State::Optional",	pkgCache::State::Optional);
	CONSTANT("AptPkg::State::Extra",	pkgCache::State::Extra);

	/* pkgCache::State::PkgSelectedState */
	CONSTANT("AptPkg::State::Unknown",	pkgCache::State::Unknown);
	CONSTANT("AptPkg::State::Install",	pkgCache::State::Install);
	CONSTANT("AptPkg::State::Hold",		pkgCache::State::Hold);
	CONSTANT("AptPkg::State::DeInstall",	pkgCache::State::DeInstall);
	CONSTANT("AptPkg::State::Purge",	pkgCache::State::Purge);

	/* pkgCache::State::PkgInstState */
	CONSTANT("AptPkg::State::Ok",		pkgCache::State::Ok);
	CONSTANT("AptPkg::State::ReInstReq",	pkgCache::State::ReInstReq);
	CONSTANT("AptPkg::State::HoldInst",	pkgCache::State::HoldInst);
	CONSTANT("AptPkg::State::HoldReInstReq",pkgCache::State::HoldReInstReq);

	/* pkgCache::State::PkgCurrentState */
	CONSTANT("AptPkg::State::NotInstalled",	pkgCache::State::NotInstalled);
	CONSTANT("AptPkg::State::UnPacked",	pkgCache::State::UnPacked);
	CONSTANT("AptPkg::State::HalfConfigured", pkgCache::State::HalfConfigured);
	CONSTANT("AptPkg::State::HalfInstalled",pkgCache::State::HalfInstalled);
	CONSTANT("AptPkg::State::ConfigFiles",	pkgCache::State::ConfigFiles);
	CONSTANT("AptPkg::State::Installed",	pkgCache::State::Installed);

	/* pkgCache::Flag::PkgFlags */
	CONSTANT("AptPkg::Flag::Auto",		pkgCache::Flag::Auto);
	CONSTANT("AptPkg::Flag::Essential",	pkgCache::Flag::Essential);
	CONSTANT("AptPkg::Flag::Important",	pkgCache::Flag::Important);
    }
