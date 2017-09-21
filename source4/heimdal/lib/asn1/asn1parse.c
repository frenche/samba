/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.0.4"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1




/* Copy the first part of user declarations.  */



#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "symbol.h"
#include "lex.h"
#include "gen_locl.h"
#include "der.h"

static Type *new_type (Typetype t);
static struct constraint_spec *new_constraint_spec(enum ctype);
static Type *new_tag(int tagclass, int tagvalue, int tagenv, Type *oldtype);
void yyerror (const char *);
static struct objid *new_objid(const char *label, int value);
static void add_oid_to_tail(struct objid *, struct objid *);
static void fix_labels(Symbol *s);

struct string_list {
    char *string;
    struct string_list *next;
};

static int default_tag_env = TE_EXPLICIT;

/* Declarations for Bison */
#define YYMALLOC malloc
#define YYFREE   free




# ifndef YY_NULLPTR
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULLPTR nullptr
#  else
#   define YY_NULLPTR 0
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* In a future release of Bison, this section will be replaced
   by #include "y.tab.h".  */
#ifndef YY_YY_Y_TAB_H_INCLUDED
# define YY_YY_Y_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    kw_ABSENT = 258,
    kw_ABSTRACT_SYNTAX = 259,
    kw_ALL = 260,
    kw_APPLICATION = 261,
    kw_AUTOMATIC = 262,
    kw_BEGIN = 263,
    kw_BIT = 264,
    kw_BMPString = 265,
    kw_BOOLEAN = 266,
    kw_BY = 267,
    kw_CHARACTER = 268,
    kw_CHOICE = 269,
    kw_CLASS = 270,
    kw_COMPONENT = 271,
    kw_COMPONENTS = 272,
    kw_CONSTRAINED = 273,
    kw_CONTAINING = 274,
    kw_DEFAULT = 275,
    kw_DEFINITIONS = 276,
    kw_EMBEDDED = 277,
    kw_ENCODED = 278,
    kw_END = 279,
    kw_ENUMERATED = 280,
    kw_EXCEPT = 281,
    kw_EXPLICIT = 282,
    kw_EXPORTS = 283,
    kw_EXTENSIBILITY = 284,
    kw_EXTERNAL = 285,
    kw_FALSE = 286,
    kw_FROM = 287,
    kw_GeneralString = 288,
    kw_GeneralizedTime = 289,
    kw_GraphicString = 290,
    kw_IA5String = 291,
    kw_IDENTIFIER = 292,
    kw_IMPLICIT = 293,
    kw_IMPLIED = 294,
    kw_IMPORTS = 295,
    kw_INCLUDES = 296,
    kw_INSTANCE = 297,
    kw_INTEGER = 298,
    kw_INTERSECTION = 299,
    kw_ISO646String = 300,
    kw_MAX = 301,
    kw_MIN = 302,
    kw_MINUS_INFINITY = 303,
    kw_NULL = 304,
    kw_NumericString = 305,
    kw_OBJECT = 306,
    kw_OCTET = 307,
    kw_OF = 308,
    kw_OPTIONAL = 309,
    kw_ObjectDescriptor = 310,
    kw_PATTERN = 311,
    kw_PDV = 312,
    kw_PLUS_INFINITY = 313,
    kw_PRESENT = 314,
    kw_PRIVATE = 315,
    kw_PrintableString = 316,
    kw_REAL = 317,
    kw_RELATIVE_OID = 318,
    kw_SEQUENCE = 319,
    kw_SET = 320,
    kw_SIZE = 321,
    kw_STRING = 322,
    kw_SYNTAX = 323,
    kw_T61String = 324,
    kw_TAGS = 325,
    kw_TRUE = 326,
    kw_TYPE_IDENTIFIER = 327,
    kw_TeletexString = 328,
    kw_UNION = 329,
    kw_UNIQUE = 330,
    kw_UNIVERSAL = 331,
    kw_UTCTime = 332,
    kw_UTF8String = 333,
    kw_UniversalString = 334,
    kw_VideotexString = 335,
    kw_VisibleString = 336,
    kw_WITH = 337,
    RANGE = 338,
    EEQUAL = 339,
    ELLIPSIS = 340,
    IDENTIFIER = 341,
    referencename = 342,
    STRING = 343,
    NUMBER = 344
  };
#endif
/* Tokens.  */
#define kw_ABSENT 258
#define kw_ABSTRACT_SYNTAX 259
#define kw_ALL 260
#define kw_APPLICATION 261
#define kw_AUTOMATIC 262
#define kw_BEGIN 263
#define kw_BIT 264
#define kw_BMPString 265
#define kw_BOOLEAN 266
#define kw_BY 267
#define kw_CHARACTER 268
#define kw_CHOICE 269
#define kw_CLASS 270
#define kw_COMPONENT 271
#define kw_COMPONENTS 272
#define kw_CONSTRAINED 273
#define kw_CONTAINING 274
#define kw_DEFAULT 275
#define kw_DEFINITIONS 276
#define kw_EMBEDDED 277
#define kw_ENCODED 278
#define kw_END 279
#define kw_ENUMERATED 280
#define kw_EXCEPT 281
#define kw_EXPLICIT 282
#define kw_EXPORTS 283
#define kw_EXTENSIBILITY 284
#define kw_EXTERNAL 285
#define kw_FALSE 286
#define kw_FROM 287
#define kw_GeneralString 288
#define kw_GeneralizedTime 289
#define kw_GraphicString 290
#define kw_IA5String 291
#define kw_IDENTIFIER 292
#define kw_IMPLICIT 293
#define kw_IMPLIED 294
#define kw_IMPORTS 295
#define kw_INCLUDES 296
#define kw_INSTANCE 297
#define kw_INTEGER 298
#define kw_INTERSECTION 299
#define kw_ISO646String 300
#define kw_MAX 301
#define kw_MIN 302
#define kw_MINUS_INFINITY 303
#define kw_NULL 304
#define kw_NumericString 305
#define kw_OBJECT 306
#define kw_OCTET 307
#define kw_OF 308
#define kw_OPTIONAL 309
#define kw_ObjectDescriptor 310
#define kw_PATTERN 311
#define kw_PDV 312
#define kw_PLUS_INFINITY 313
#define kw_PRESENT 314
#define kw_PRIVATE 315
#define kw_PrintableString 316
#define kw_REAL 317
#define kw_RELATIVE_OID 318
#define kw_SEQUENCE 319
#define kw_SET 320
#define kw_SIZE 321
#define kw_STRING 322
#define kw_SYNTAX 323
#define kw_T61String 324
#define kw_TAGS 325
#define kw_TRUE 326
#define kw_TYPE_IDENTIFIER 327
#define kw_TeletexString 328
#define kw_UNION 329
#define kw_UNIQUE 330
#define kw_UNIVERSAL 331
#define kw_UTCTime 332
#define kw_UTF8String 333
#define kw_UniversalString 334
#define kw_VideotexString 335
#define kw_VisibleString 336
#define kw_WITH 337
#define RANGE 338
#define EEQUAL 339
#define ELLIPSIS 340
#define IDENTIFIER 341
#define referencename 342
#define STRING 343
#define NUMBER 344

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{


    int64_t constant;
    struct value *value;
    struct range *range;
    char *name;
    Type *type;
    Member *member;
    struct objid *objid;
    char *defval;
    struct string_list *sl;
    struct tagtype tag;
    struct memhead *members;
    struct constraint_spec *constraint_spec;


};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (void);

#endif /* !YY_YY_Y_TAB_H_INCLUDED  */

/* Copy the second part of user declarations.  */



#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef YY_ATTRIBUTE
# if (defined __GNUC__                                               \
      && (2 < __GNUC__ || (__GNUC__ == 2 && 96 <= __GNUC_MINOR__)))  \
     || defined __SUNPRO_C && 0x5110 <= __SUNPRO_C
#  define YY_ATTRIBUTE(Spec) __attribute__(Spec)
# else
#  define YY_ATTRIBUTE(Spec) /* empty */
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# define YY_ATTRIBUTE_PURE   YY_ATTRIBUTE ((__pure__))
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# define YY_ATTRIBUTE_UNUSED YY_ATTRIBUTE ((__unused__))
#endif

#if !defined _Noreturn \
     && (!defined __STDC_VERSION__ || __STDC_VERSION__ < 201112)
# if defined _MSC_VER && 1200 <= _MSC_VER
#  define _Noreturn __declspec (noreturn)
# else
#  define _Noreturn YY_ATTRIBUTE ((__noreturn__))
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")\
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif


#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYSIZE_T yynewbytes;                                            \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / sizeof (*yyptr);                          \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  6
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   203

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  98
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  69
/* YYNRULES -- Number of rules.  */
#define YYNRULES  140
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  220

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   344

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      92,    93,     2,     2,    91,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,    90,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    96,     2,    97,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    94,     2,    95,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   240,   240,   247,   249,   251,   253,   256,   258,   261,
     262,   265,   266,   269,   270,   273,   274,   277,   289,   295,
     296,   299,   300,   303,   304,   307,   313,   321,   331,   332,
     333,   336,   337,   338,   339,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,   352,   359,   369,   377,   385,
     396,   401,   407,   415,   421,   426,   430,   443,   451,   454,
     461,   469,   475,   489,   497,   498,   503,   509,   517,   532,
     538,   546,   554,   561,   562,   565,   576,   581,   588,   604,
     610,   613,   614,   617,   623,   631,   641,   647,   665,   674,
     677,   681,   685,   692,   695,   699,   706,   717,   720,   725,
     730,   735,   740,   745,   750,   755,   763,   769,   774,   785,
     796,   802,   808,   816,   822,   829,   842,   843,   846,   853,
     856,   867,   871,   882,   888,   889,   892,   893,   894,   895,
     896,   899,   902,   905,   916,   924,   930,   938,   946,   949,
     954
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "kw_ABSENT", "kw_ABSTRACT_SYNTAX",
  "kw_ALL", "kw_APPLICATION", "kw_AUTOMATIC", "kw_BEGIN", "kw_BIT",
  "kw_BMPString", "kw_BOOLEAN", "kw_BY", "kw_CHARACTER", "kw_CHOICE",
  "kw_CLASS", "kw_COMPONENT", "kw_COMPONENTS", "kw_CONSTRAINED",
  "kw_CONTAINING", "kw_DEFAULT", "kw_DEFINITIONS", "kw_EMBEDDED",
  "kw_ENCODED", "kw_END", "kw_ENUMERATED", "kw_EXCEPT", "kw_EXPLICIT",
  "kw_EXPORTS", "kw_EXTENSIBILITY", "kw_EXTERNAL", "kw_FALSE", "kw_FROM",
  "kw_GeneralString", "kw_GeneralizedTime", "kw_GraphicString",
  "kw_IA5String", "kw_IDENTIFIER", "kw_IMPLICIT", "kw_IMPLIED",
  "kw_IMPORTS", "kw_INCLUDES", "kw_INSTANCE", "kw_INTEGER",
  "kw_INTERSECTION", "kw_ISO646String", "kw_MAX", "kw_MIN",
  "kw_MINUS_INFINITY", "kw_NULL", "kw_NumericString", "kw_OBJECT",
  "kw_OCTET", "kw_OF", "kw_OPTIONAL", "kw_ObjectDescriptor", "kw_PATTERN",
  "kw_PDV", "kw_PLUS_INFINITY", "kw_PRESENT", "kw_PRIVATE",
  "kw_PrintableString", "kw_REAL", "kw_RELATIVE_OID", "kw_SEQUENCE",
  "kw_SET", "kw_SIZE", "kw_STRING", "kw_SYNTAX", "kw_T61String", "kw_TAGS",
  "kw_TRUE", "kw_TYPE_IDENTIFIER", "kw_TeletexString", "kw_UNION",
  "kw_UNIQUE", "kw_UNIVERSAL", "kw_UTCTime", "kw_UTF8String",
  "kw_UniversalString", "kw_VideotexString", "kw_VisibleString", "kw_WITH",
  "RANGE", "EEQUAL", "ELLIPSIS", "IDENTIFIER", "referencename", "STRING",
  "NUMBER", "';'", "','", "'('", "')'", "'{'", "'}'", "'['", "']'",
  "$accept", "ModuleDefinition", "TagDefault", "ExtensionDefault",
  "ModuleBody", "Imports", "SymbolsImported", "SymbolsFromModuleList",
  "SymbolsFromModule", "Exports", "AssignmentList", "Assignment",
  "referencenames", "TypeAssignment", "Type", "BuiltinType", "BooleanType",
  "range", "IntegerType", "NamedNumberList", "NamedNumber",
  "EnumeratedType", "Enumerations", "BitStringType",
  "ObjectIdentifierType", "OctetStringType", "NullType", "size",
  "SequenceType", "SequenceOfType", "SetType", "SetOfType", "ChoiceType",
  "ReferencedType", "DefinedType", "UsefulType", "ConstrainedType",
  "Constraint", "ConstraintSpec", "GeneralConstraint",
  "ContentsConstraint", "UserDefinedConstraint", "TaggedType", "Tag",
  "Class", "tagenv", "ValueAssignment", "CharacterStringType",
  "RestrictedCharactedStringType", "ComponentTypeList", "NamedType",
  "ComponentType", "NamedBitList", "NamedBit", "objid_opt", "objid",
  "objid_list", "objid_element", "Value", "BuiltinValue",
  "ReferencedValue", "DefinedValue", "Valuereference",
  "CharacterStringValue", "BooleanValue", "IntegerValue", "SignedNumber",
  "NullValue", "ObjectIdentifierValue", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   344,
      59,    44,    40,    41,   123,   125,    91,    93
};
# endif

#define YYPACT_NINF -119

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-119)))

#define YYTABLE_NINF -11

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -43,   -56,    47,   -65,    29,  -119,  -119,   -31,  -119,   -25,
     -65,     4,    -1,  -119,  -119,    17,    20,    26,    50,    13,
    -119,  -119,  -119,    63,    24,  -119,  -119,   104,     8,    -2,
      89,    74,  -119,    33,    25,  -119,    34,    39,    34,  -119,
      37,    34,  -119,    98,    58,  -119,    39,  -119,  -119,  -119,
    -119,  -119,    52,    66,  -119,  -119,    51,    53,  -119,  -119,
    -119,   -79,  -119,   109,    81,  -119,   -60,   -48,  -119,  -119,
    -119,  -119,  -119,   107,  -119,     2,   -74,  -119,  -119,  -119,
    -119,  -119,  -119,  -119,  -119,  -119,  -119,  -119,  -119,  -119,
    -119,  -119,  -119,  -119,  -119,   -18,  -119,  -119,  -119,   -56,
      55,    65,    67,   -12,    67,  -119,  -119,    86,    68,   -70,
     102,   107,   -69,    69,  -119,  -119,  -119,    73,    40,    10,
    -119,  -119,  -119,   107,  -119,    71,   107,   -47,   -13,  -119,
      72,    75,  -119,    70,  -119,    80,  -119,  -119,  -119,  -119,
    -119,  -119,   -71,  -119,  -119,  -119,  -119,  -119,  -119,  -119,
    -119,  -119,  -119,   -46,  -119,  -119,  -119,   -39,   107,    69,
    -119,   -38,    76,  -119,   155,   107,   157,    77,  -119,  -119,
    -119,    69,    82,   -10,  -119,    69,   -22,  -119,    40,  -119,
      87,    19,  -119,    40,     9,  -119,  -119,  -119,    69,  -119,
    -119,    83,   -19,    40,  -119,    90,    71,  -119,  -119,  -119,
    -119,    85,  -119,  -119,    88,    94,    96,    95,   163,  -119,
      99,  -119,  -119,  -119,  -119,  -119,  -119,    40,  -119,  -119
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       0,   117,     0,   119,     0,   116,     1,   122,   123,     0,
     119,     6,     0,   118,   120,     0,     0,     0,     8,     0,
       5,     3,     4,     0,     0,   121,     7,     0,    20,     0,
       0,    12,    19,    26,     0,     2,    14,     0,     0,    18,
       0,    13,    15,     0,     0,     9,    21,    23,    24,    25,
      11,    16,     0,     0,   104,    45,     0,     0,    98,    76,
     103,    50,    63,     0,     0,   101,    64,     0,    99,    77,
     100,   105,   102,     0,    75,    89,     0,    28,    32,    36,
      35,    31,    38,    39,    37,    40,    41,    42,    43,    34,
      29,    73,    74,    30,    44,    93,    33,    97,    22,   117,
      59,     0,     0,     0,     0,    51,    61,    64,     0,     0,
       0,     0,     0,    27,    91,    92,    90,     0,     0,     0,
      78,    94,    95,     0,    17,     0,     0,     0,   110,   106,
       0,    58,    53,     0,   136,     0,   139,   135,   133,   134,
     138,   140,     0,   124,   125,   131,   132,   127,   126,   128,
     137,   130,   129,     0,    62,    65,    67,     0,     0,    71,
      70,     0,     0,    96,     0,     0,     0,     0,    80,    81,
      82,    87,     0,     0,   113,   109,     0,    72,     0,   111,
       0,     0,    57,     0,     0,    49,    52,    66,    68,    69,
      88,     0,    83,     0,    79,     0,     0,    60,   108,   107,
     112,     0,    55,    54,     0,     0,     0,     0,     0,    84,
       0,   114,    56,    48,    47,    46,    86,     0,   115,    85
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -119,  -119,  -119,  -119,  -119,  -119,  -119,  -119,   141,  -119,
     137,  -119,   -15,  -119,   -72,  -119,  -119,    91,  -119,    92,
      14,  -119,  -119,  -119,  -119,  -119,  -119,    84,  -119,  -119,
    -119,  -119,  -119,  -119,  -119,  -119,  -119,  -119,  -119,  -119,
    -119,  -119,  -119,  -119,  -119,  -119,  -119,  -119,  -119,   -82,
    -119,    18,  -119,     5,   101,     1,   187,  -119,  -118,  -119,
    -119,  -119,  -119,  -119,  -119,  -119,    22,  -119,  -119
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     2,    18,    24,    30,    37,    40,    41,    42,    31,
      45,    46,    43,    47,    76,    77,    78,   105,    79,   131,
     132,    80,   133,    81,    82,    83,    84,   110,    85,    86,
      87,    88,    89,    90,    91,    92,    93,   120,   167,   168,
     169,   170,    94,    95,   117,   123,    48,    96,    97,   127,
     128,   129,   173,   174,     4,   141,     9,    10,   142,   143,
     144,   145,   146,   147,   148,   149,   150,   151,   152
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
     163,   113,     5,    32,   208,   111,   108,   178,   114,   121,
     118,    15,   184,   103,    34,   104,   126,   126,   119,   134,
     122,     7,   185,    49,     8,   156,   160,   157,   164,   165,
     161,    16,   -10,   166,   109,   135,    29,   136,     3,   159,
     134,   179,    17,     1,   176,   181,   112,     6,   177,   186,
      11,   171,   176,   176,   175,   205,   187,   189,   136,   137,
     200,    12,   115,   198,   126,   204,   206,    53,    54,    55,
      13,   134,    56,   119,   138,   209,   139,   140,   116,    23,
     137,   196,     3,    57,    33,   197,   188,    20,    19,   136,
      21,    58,    59,   192,    60,   138,    22,   139,   140,   219,
       5,    61,    26,     3,   202,   130,    25,    62,    27,    63,
      64,   137,    28,    35,    36,    39,    53,    54,    55,    65,
      33,    56,    66,    67,    38,    44,   138,    50,   139,   140,
      52,    68,    57,   100,     3,    69,    70,    71,    99,    72,
      58,    59,    73,    60,    74,   101,   106,   102,   107,   125,
      61,   126,   108,   130,    75,   158,    62,   172,    63,    64,
     103,   119,   162,   183,   180,   182,   181,   191,    65,   193,
     194,    66,    67,   190,   195,   217,   140,   207,   212,   210,
      68,   213,    51,    98,    69,    70,    71,   214,    72,   215,
     216,   154,   218,    74,   199,   203,   153,    14,     0,   155,
     124,   211,   201,    75
};

static const yytype_int16 yycheck[] =
{
     118,    73,     1,     5,    23,    53,    66,    20,     6,    27,
      84,     7,    83,    92,    29,    94,    86,    86,    92,    31,
      38,    86,    93,    38,    89,    95,    95,   109,    18,    19,
     112,    27,    24,    23,    94,    47,    28,    49,    94,   111,
      31,    54,    38,    86,    91,    91,    94,     0,    95,    95,
      21,   123,    91,    91,   126,    46,    95,    95,    49,    71,
     178,    92,    60,    85,    86,   183,   184,     9,    10,    11,
      95,    31,    14,    92,    86,   193,    88,    89,    76,    29,
      71,    91,    94,    25,    86,    95,   158,    70,    89,    49,
      70,    33,    34,   165,    36,    86,    70,    88,    89,   217,
      99,    43,    39,    94,    85,    86,    93,    49,    84,    51,
      52,    71,     8,    24,    40,    90,     9,    10,    11,    61,
      86,    14,    64,    65,    91,    86,    86,    90,    88,    89,
      32,    73,    25,    67,    94,    77,    78,    79,    86,    81,
      33,    34,    84,    36,    86,    94,    37,    94,    67,    94,
      43,    86,    66,    86,    96,    53,    49,    86,    51,    52,
      92,    92,    89,    83,    92,    95,    91,    12,    61,    12,
      93,    64,    65,    97,    92,    12,    89,    94,    93,    89,
      73,    93,    41,    46,    77,    78,    79,    93,    81,    93,
      95,   107,    93,    86,   176,   181,   104,    10,    -1,   108,
      99,   196,   180,    96
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    86,    99,    94,   152,   153,     0,    86,    89,   154,
     155,    21,    92,    95,   154,     7,    27,    38,   100,    89,
      70,    70,    70,    29,   101,    93,    39,    84,     8,    28,
     102,   107,     5,    86,   110,    24,    40,   103,    91,    90,
     104,   105,   106,   110,    86,   108,   109,   111,   144,   110,
      90,   106,    32,     9,    10,    11,    14,    25,    33,    34,
      36,    43,    49,    51,    52,    61,    64,    65,    73,    77,
      78,    79,    81,    84,    86,    96,   112,   113,   114,   116,
     119,   121,   122,   123,   124,   126,   127,   128,   129,   130,
     131,   132,   133,   134,   140,   141,   145,   146,   108,    86,
      67,    94,    94,    92,    94,   115,    37,    67,    66,    94,
     125,    53,    94,   112,     6,    60,    76,   142,    84,    92,
     135,    27,    38,   143,   152,    94,    86,   147,   148,   149,
      86,   117,   118,   120,    31,    47,    49,    71,    86,    88,
      89,   153,   156,   157,   158,   159,   160,   161,   162,   163,
     164,   165,   166,   117,   125,   115,    95,   147,    53,   112,
      95,   147,    89,   156,    18,    19,    23,   136,   137,   138,
     139,   112,    86,   150,   151,   112,    91,    95,    20,    54,
      92,    91,    95,    83,    83,    93,    95,    95,   112,    95,
      97,    12,   112,    12,    93,    92,    91,    95,    85,   149,
     156,   164,    85,   118,   156,    46,   156,    94,    23,   156,
      89,   151,    93,    93,    93,    93,    95,    12,    93,   156
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    98,    99,   100,   100,   100,   100,   101,   101,   102,
     102,   103,   103,   104,   104,   105,   105,   106,   107,   107,
     107,   108,   108,   109,   109,   110,   110,   111,   112,   112,
     112,   113,   113,   113,   113,   113,   113,   113,   113,   113,
     113,   113,   113,   113,   113,   114,   115,   115,   115,   115,
     116,   116,   116,   117,   117,   117,   118,   119,   120,   121,
     121,   122,   123,   124,   125,   125,   126,   126,   127,   128,
     128,   129,   130,   131,   131,   132,   133,   133,   134,   135,
     136,   137,   137,   138,   138,   138,   139,   140,   141,   142,
     142,   142,   142,   143,   143,   143,   144,   145,   146,   146,
     146,   146,   146,   146,   146,   146,   147,   147,   147,   148,
     149,   149,   149,   150,   150,   151,   152,   152,   153,   154,
     154,   155,   155,   155,   156,   156,   157,   157,   157,   157,
     157,   158,   159,   160,   161,   162,   162,   163,   164,   165,
     166
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     9,     2,     2,     2,     0,     2,     0,     3,
       0,     3,     0,     1,     0,     1,     2,     4,     3,     2,
       0,     1,     2,     1,     1,     3,     1,     3,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     5,     5,     5,     3,
       1,     2,     4,     1,     3,     3,     4,     4,     1,     2,
       5,     2,     3,     1,     0,     2,     4,     3,     4,     4,
       3,     3,     4,     1,     1,     1,     1,     1,     2,     3,
       1,     1,     1,     2,     3,     5,     4,     3,     4,     0,
       1,     1,     1,     0,     1,     1,     4,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     3,     3,     2,
       1,     2,     3,     1,     3,     4,     1,     0,     3,     0,
       2,     4,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
do                                                              \
  if (yychar == YYEMPTY)                                        \
    {                                                           \
      yychar = (Token);                                         \
      yylval = (Value);                                         \
      YYPOPSTACK (yylen);                                       \
      yystate = *yyssp;                                         \
      goto yybackup;                                            \
    }                                                           \
  else                                                          \
    {                                                           \
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;                                                  \
    }                                                           \
while (0)

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256



/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)

/* This macro is provided for backward compatibility. */
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*----------------------------------------.
| Print this symbol's value on YYOUTPUT.  |
`----------------------------------------*/

static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
  YYUSE (yytype);
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyoutput, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yytype_int16 *yyssp, YYSTYPE *yyvsp, int yyrule)
{
  unsigned long int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[yyssp[yyi + 1 - yynrhs]],
                       &(yyvsp[(yyi + 1) - (yynrhs)])
                                              );
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
yystrlen (const char *yystr)
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            /* Fall through.  */
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
{
  YYUSE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;


/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        YYSTYPE *yyvs1 = yyvs;
        yytype_int16 *yyss1 = yyss;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * sizeof (*yyssp),
                    &yyvs1, yysize * sizeof (*yyvsp),
                    &yystacksize);

        yyss = yyss1;
        yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yytype_int16 *yyss1 = yyss;
        union yyalloc *yyptr =
          (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
                  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 2:

    {
			checkundefined();
		}

    break;

  case 3:

    { default_tag_env = TE_EXPLICIT; }

    break;

  case 4:

    { default_tag_env = TE_IMPLICIT; }

    break;

  case 5:

    { lex_error_message("automatic tagging is not supported"); }

    break;

  case 7:

    { lex_error_message("no extensibility options supported"); }

    break;

  case 17:

    {
		    struct string_list *sl;
		    for(sl = (yyvsp[-3].sl); sl != NULL; sl = sl->next) {
			Symbol *s = addsym(sl->string);
			s->stype = Stype;
			gen_template_import(s);
		    }
		    add_import((yyvsp[-1].name));
		}

    break;

  case 18:

    {
		    struct string_list *sl;
		    for(sl = (yyvsp[-1].sl); sl != NULL; sl = sl->next)
			add_export(sl->string);
		}

    break;

  case 25:

    {
		    (yyval.sl) = emalloc(sizeof(*(yyval.sl)));
		    (yyval.sl)->string = (yyvsp[-2].name);
		    (yyval.sl)->next = (yyvsp[0].sl);
		}

    break;

  case 26:

    {
		    (yyval.sl) = emalloc(sizeof(*(yyval.sl)));
		    (yyval.sl)->string = (yyvsp[0].name);
		    (yyval.sl)->next = NULL;
		}

    break;

  case 27:

    {
		    Symbol *s = addsym ((yyvsp[-2].name));
		    s->stype = Stype;
		    s->type = (yyvsp[0].type);
		    fix_labels(s);
		    generate_type (s);
		}

    break;

  case 45:

    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_Boolean,
				     TE_EXPLICIT, new_type(TBoolean));
		}

    break;

  case 46:

    {
		    if((yyvsp[-3].value)->type != integervalue)
			lex_error_message("Non-integer used in first part of range");
		    if((yyvsp[-3].value)->type != integervalue)
			lex_error_message("Non-integer in second part of range");
		    (yyval.range) = ecalloc(1, sizeof(*(yyval.range)));
		    (yyval.range)->min = (yyvsp[-3].value)->u.integervalue;
		    (yyval.range)->max = (yyvsp[-1].value)->u.integervalue;
		}

    break;

  case 47:

    {
		    if((yyvsp[-3].value)->type != integervalue)
			lex_error_message("Non-integer in first part of range");
		    (yyval.range) = ecalloc(1, sizeof(*(yyval.range)));
		    (yyval.range)->min = (yyvsp[-3].value)->u.integervalue;
		    (yyval.range)->max = INT_MAX;
		}

    break;

  case 48:

    {
		    if((yyvsp[-1].value)->type != integervalue)
			lex_error_message("Non-integer in second part of range");
		    (yyval.range) = ecalloc(1, sizeof(*(yyval.range)));
		    (yyval.range)->min = INT_MIN;
		    (yyval.range)->max = (yyvsp[-1].value)->u.integervalue;
		}

    break;

  case 49:

    {
		    if((yyvsp[-1].value)->type != integervalue)
			lex_error_message("Non-integer used in limit");
		    (yyval.range) = ecalloc(1, sizeof(*(yyval.range)));
		    (yyval.range)->min = (yyvsp[-1].value)->u.integervalue;
		    (yyval.range)->max = (yyvsp[-1].value)->u.integervalue;
		}

    break;

  case 50:

    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_Integer,
				     TE_EXPLICIT, new_type(TInteger));
		}

    break;

  case 51:

    {
			(yyval.type) = new_type(TInteger);
			(yyval.type)->range = (yyvsp[0].range);
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_Integer, TE_EXPLICIT, (yyval.type));
		}

    break;

  case 52:

    {
		  (yyval.type) = new_type(TInteger);
		  (yyval.type)->members = (yyvsp[-1].members);
		  (yyval.type) = new_tag(ASN1_C_UNIV, UT_Integer, TE_EXPLICIT, (yyval.type));
		}

    break;

  case 53:

    {
			(yyval.members) = emalloc(sizeof(*(yyval.members)));
			ASN1_TAILQ_INIT((yyval.members));
			ASN1_TAILQ_INSERT_HEAD((yyval.members), (yyvsp[0].member), members);
		}

    break;

  case 54:

    {
			ASN1_TAILQ_INSERT_TAIL((yyvsp[-2].members), (yyvsp[0].member), members);
			(yyval.members) = (yyvsp[-2].members);
		}

    break;

  case 55:

    { (yyval.members) = (yyvsp[-2].members); }

    break;

  case 56:

    {
			(yyval.member) = emalloc(sizeof(*(yyval.member)));
			(yyval.member)->name = (yyvsp[-3].name);
			(yyval.member)->gen_name = estrdup((yyvsp[-3].name));
			output_name ((yyval.member)->gen_name);
			(yyval.member)->val = (yyvsp[-1].constant);
			(yyval.member)->optional = 0;
			(yyval.member)->ellipsis = 0;
			(yyval.member)->type = NULL;
		}

    break;

  case 57:

    {
		  (yyval.type) = new_type(TInteger);
		  (yyval.type)->members = (yyvsp[-1].members);
		  (yyval.type) = new_tag(ASN1_C_UNIV, UT_Enumerated, TE_EXPLICIT, (yyval.type));
		}

    break;

  case 59:

    {
		  (yyval.type) = new_type(TBitString);
		  (yyval.type)->members = emalloc(sizeof(*(yyval.type)->members));
		  ASN1_TAILQ_INIT((yyval.type)->members);
		  (yyval.type) = new_tag(ASN1_C_UNIV, UT_BitString, TE_EXPLICIT, (yyval.type));
		}

    break;

  case 60:

    {
		  (yyval.type) = new_type(TBitString);
		  (yyval.type)->members = (yyvsp[-1].members);
		  (yyval.type) = new_tag(ASN1_C_UNIV, UT_BitString, TE_EXPLICIT, (yyval.type));
		}

    break;

  case 61:

    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_OID,
				     TE_EXPLICIT, new_type(TOID));
		}

    break;

  case 62:

    {
		    Type *t = new_type(TOctetString);
		    t->range = (yyvsp[0].range);
		    if (t->range) {
			if (t->range->min < 0)
			    lex_error_message("can't use a negative SIZE range "
					      "length for OCTET STRING");
		    }
		    (yyval.type) = new_tag(ASN1_C_UNIV, UT_OctetString,
				 TE_EXPLICIT, t);
		}

    break;

  case 63:

    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_Null,
				     TE_EXPLICIT, new_type(TNull));
		}

    break;

  case 64:

    { (yyval.range) = NULL; }

    break;

  case 65:

    { (yyval.range) = (yyvsp[0].range); }

    break;

  case 66:

    {
		  (yyval.type) = new_type(TSequence);
		  (yyval.type)->members = (yyvsp[-1].members);
		  (yyval.type) = new_tag(ASN1_C_UNIV, UT_Sequence, default_tag_env, (yyval.type));
		}

    break;

  case 67:

    {
		  (yyval.type) = new_type(TSequence);
		  (yyval.type)->members = NULL;
		  (yyval.type) = new_tag(ASN1_C_UNIV, UT_Sequence, default_tag_env, (yyval.type));
		}

    break;

  case 68:

    {
		  (yyval.type) = new_type(TSequenceOf);
		  (yyval.type)->range = (yyvsp[-2].range);
		  if ((yyval.type)->range) {
		      if ((yyval.type)->range->min < 0)
			  lex_error_message("can't use a negative SIZE range "
					    "length for SEQUENCE OF");
		    }

		  (yyval.type)->subtype = (yyvsp[0].type);
		  (yyval.type) = new_tag(ASN1_C_UNIV, UT_Sequence, default_tag_env, (yyval.type));
		}

    break;

  case 69:

    {
		  (yyval.type) = new_type(TSet);
		  (yyval.type)->members = (yyvsp[-1].members);
		  (yyval.type) = new_tag(ASN1_C_UNIV, UT_Set, default_tag_env, (yyval.type));
		}

    break;

  case 70:

    {
		  (yyval.type) = new_type(TSet);
		  (yyval.type)->members = NULL;
		  (yyval.type) = new_tag(ASN1_C_UNIV, UT_Set, default_tag_env, (yyval.type));
		}

    break;

  case 71:

    {
		  (yyval.type) = new_type(TSetOf);
		  (yyval.type)->subtype = (yyvsp[0].type);
		  (yyval.type) = new_tag(ASN1_C_UNIV, UT_Set, default_tag_env, (yyval.type));
		}

    break;

  case 72:

    {
		  (yyval.type) = new_type(TChoice);
		  (yyval.type)->members = (yyvsp[-1].members);
		}

    break;

  case 75:

    {
		  Symbol *s = addsym((yyvsp[0].name));
		  (yyval.type) = new_type(TType);
		  if(s->stype != Stype && s->stype != SUndefined)
		    lex_error_message ("%s is not a type\n", (yyvsp[0].name));
		  else
		    (yyval.type)->symbol = s;
		}

    break;

  case 76:

    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_GeneralizedTime,
				     TE_EXPLICIT, new_type(TGeneralizedTime));
		}

    break;

  case 77:

    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_UTCTime,
				     TE_EXPLICIT, new_type(TUTCTime));
		}

    break;

  case 78:

    {
		    /* if (Constraint.type == contentConstrant) {
		       assert(Constraint.u.constraint.type == octetstring|bitstring-w/o-NamedBitList); // remember to check type reference too
		       if (Constraint.u.constraint.type) {
		         assert((Constraint.u.constraint.type.length % 8) == 0);
		       }
		      }
		      if (Constraint.u.constraint.encoding) {
		        type == der-oid|ber-oid
		      }
		    */
		}

    break;

  case 79:

    {
		    (yyval.constraint_spec) = (yyvsp[-1].constraint_spec);
		}

    break;

  case 83:

    {
		    (yyval.constraint_spec) = new_constraint_spec(CT_CONTENTS);
		    (yyval.constraint_spec)->u.content.type = (yyvsp[0].type);
		    (yyval.constraint_spec)->u.content.encoding = NULL;
		}

    break;

  case 84:

    {
		    if ((yyvsp[0].value)->type != objectidentifiervalue)
			lex_error_message("Non-OID used in ENCODED BY constraint");
		    (yyval.constraint_spec) = new_constraint_spec(CT_CONTENTS);
		    (yyval.constraint_spec)->u.content.type = NULL;
		    (yyval.constraint_spec)->u.content.encoding = (yyvsp[0].value);
		}

    break;

  case 85:

    {
		    if ((yyvsp[0].value)->type != objectidentifiervalue)
			lex_error_message("Non-OID used in ENCODED BY constraint");
		    (yyval.constraint_spec) = new_constraint_spec(CT_CONTENTS);
		    (yyval.constraint_spec)->u.content.type = (yyvsp[-3].type);
		    (yyval.constraint_spec)->u.content.encoding = (yyvsp[0].value);
		}

    break;

  case 86:

    {
		    (yyval.constraint_spec) = new_constraint_spec(CT_USER);
		}

    break;

  case 87:

    {
			(yyval.type) = new_type(TTag);
			(yyval.type)->tag = (yyvsp[-2].tag);
			(yyval.type)->tag.tagenv = (yyvsp[-1].constant);
			if (template_flag) {
			    (yyval.type)->subtype = (yyvsp[0].type);
			} else {
			    if((yyvsp[0].type)->type == TTag && (yyvsp[-1].constant) == TE_IMPLICIT) {
				(yyval.type)->subtype = (yyvsp[0].type)->subtype;
				free((yyvsp[0].type));
			    } else {
				(yyval.type)->subtype = (yyvsp[0].type);
			    }
			}
		}

    break;

  case 88:

    {
			(yyval.tag).tagclass = (yyvsp[-2].constant);
			(yyval.tag).tagvalue = (yyvsp[-1].constant);
			(yyval.tag).tagenv = default_tag_env;
		}

    break;

  case 89:

    {
			(yyval.constant) = ASN1_C_CONTEXT;
		}

    break;

  case 90:

    {
			(yyval.constant) = ASN1_C_UNIV;
		}

    break;

  case 91:

    {
			(yyval.constant) = ASN1_C_APPL;
		}

    break;

  case 92:

    {
			(yyval.constant) = ASN1_C_PRIVATE;
		}

    break;

  case 93:

    {
			(yyval.constant) = default_tag_env;
		}

    break;

  case 94:

    {
			(yyval.constant) = default_tag_env;
		}

    break;

  case 95:

    {
			(yyval.constant) = TE_IMPLICIT;
		}

    break;

  case 96:

    {
			Symbol *s;
			s = addsym ((yyvsp[-3].name));

			s->stype = SValue;
			s->value = (yyvsp[0].value);
			generate_constant (s);
		}

    break;

  case 98:

    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_GeneralString,
				     TE_EXPLICIT, new_type(TGeneralString));
		}

    break;

  case 99:

    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_TeletexString,
				     TE_EXPLICIT, new_type(TTeletexString));
		}

    break;

  case 100:

    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_UTF8String,
				     TE_EXPLICIT, new_type(TUTF8String));
		}

    break;

  case 101:

    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_PrintableString,
				     TE_EXPLICIT, new_type(TPrintableString));
		}

    break;

  case 102:

    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_VisibleString,
				     TE_EXPLICIT, new_type(TVisibleString));
		}

    break;

  case 103:

    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_IA5String,
				     TE_EXPLICIT, new_type(TIA5String));
		}

    break;

  case 104:

    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_BMPString,
				     TE_EXPLICIT, new_type(TBMPString));
		}

    break;

  case 105:

    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_UniversalString,
				     TE_EXPLICIT, new_type(TUniversalString));
		}

    break;

  case 106:

    {
			(yyval.members) = emalloc(sizeof(*(yyval.members)));
			ASN1_TAILQ_INIT((yyval.members));
			ASN1_TAILQ_INSERT_HEAD((yyval.members), (yyvsp[0].member), members);
		}

    break;

  case 107:

    {
			ASN1_TAILQ_INSERT_TAIL((yyvsp[-2].members), (yyvsp[0].member), members);
			(yyval.members) = (yyvsp[-2].members);
		}

    break;

  case 108:

    {
		        struct member *m = ecalloc(1, sizeof(*m));
			m->name = estrdup("...");
			m->gen_name = estrdup("asn1_ellipsis");
			m->ellipsis = 1;
			ASN1_TAILQ_INSERT_TAIL((yyvsp[-2].members), m, members);
			(yyval.members) = (yyvsp[-2].members);
		}

    break;

  case 109:

    {
		  (yyval.member) = emalloc(sizeof(*(yyval.member)));
		  (yyval.member)->name = (yyvsp[-1].name);
		  (yyval.member)->gen_name = estrdup((yyvsp[-1].name));
		  output_name ((yyval.member)->gen_name);
		  (yyval.member)->type = (yyvsp[0].type);
		  (yyval.member)->ellipsis = 0;
		}

    break;

  case 110:

    {
			(yyval.member) = (yyvsp[0].member);
			(yyval.member)->optional = 0;
			(yyval.member)->defval = NULL;
		}

    break;

  case 111:

    {
			(yyval.member) = (yyvsp[-1].member);
			(yyval.member)->optional = 1;
			(yyval.member)->defval = NULL;
		}

    break;

  case 112:

    {
			(yyval.member) = (yyvsp[-2].member);
			(yyval.member)->optional = 0;
			(yyval.member)->defval = (yyvsp[0].value);
		}

    break;

  case 113:

    {
			(yyval.members) = emalloc(sizeof(*(yyval.members)));
			ASN1_TAILQ_INIT((yyval.members));
			ASN1_TAILQ_INSERT_HEAD((yyval.members), (yyvsp[0].member), members);
		}

    break;

  case 114:

    {
			ASN1_TAILQ_INSERT_TAIL((yyvsp[-2].members), (yyvsp[0].member), members);
			(yyval.members) = (yyvsp[-2].members);
		}

    break;

  case 115:

    {
		  (yyval.member) = emalloc(sizeof(*(yyval.member)));
		  (yyval.member)->name = (yyvsp[-3].name);
		  (yyval.member)->gen_name = estrdup((yyvsp[-3].name));
		  output_name ((yyval.member)->gen_name);
		  (yyval.member)->val = (yyvsp[-1].constant);
		  (yyval.member)->optional = 0;
		  (yyval.member)->ellipsis = 0;
		  (yyval.member)->type = NULL;
		}

    break;

  case 117:

    { (yyval.objid) = NULL; }

    break;

  case 118:

    {
			(yyval.objid) = (yyvsp[-1].objid);
		}

    break;

  case 119:

    {
			(yyval.objid) = NULL;
		}

    break;

  case 120:

    {
		        if ((yyvsp[0].objid)) {
				(yyval.objid) = (yyvsp[0].objid);
				add_oid_to_tail((yyvsp[0].objid), (yyvsp[-1].objid));
			} else {
				(yyval.objid) = (yyvsp[-1].objid);
			}
		}

    break;

  case 121:

    {
			(yyval.objid) = new_objid((yyvsp[-3].name), (yyvsp[-1].constant));
		}

    break;

  case 122:

    {
		    Symbol *s = addsym((yyvsp[0].name));
		    if(s->stype != SValue ||
		       s->value->type != objectidentifiervalue) {
			lex_error_message("%s is not an object identifier\n",
				      s->name);
			exit(1);
		    }
		    (yyval.objid) = s->value->u.objectidentifiervalue;
		}

    break;

  case 123:

    {
		    (yyval.objid) = new_objid(NULL, (yyvsp[0].constant));
		}

    break;

  case 133:

    {
			Symbol *s = addsym((yyvsp[0].name));
			if(s->stype != SValue)
				lex_error_message ("%s is not a value\n",
						s->name);
			else
				(yyval.value) = s->value;
		}

    break;

  case 134:

    {
			(yyval.value) = emalloc(sizeof(*(yyval.value)));
			(yyval.value)->type = stringvalue;
			(yyval.value)->u.stringvalue = (yyvsp[0].name);
		}

    break;

  case 135:

    {
			(yyval.value) = emalloc(sizeof(*(yyval.value)));
			(yyval.value)->type = booleanvalue;
			(yyval.value)->u.booleanvalue = 0;
		}

    break;

  case 136:

    {
			(yyval.value) = emalloc(sizeof(*(yyval.value)));
			(yyval.value)->type = booleanvalue;
			(yyval.value)->u.booleanvalue = 0;
		}

    break;

  case 137:

    {
			(yyval.value) = emalloc(sizeof(*(yyval.value)));
			(yyval.value)->type = integervalue;
			(yyval.value)->u.integervalue = (yyvsp[0].constant);
		}

    break;

  case 139:

    {
		}

    break;

  case 140:

    {
			(yyval.value) = emalloc(sizeof(*(yyval.value)));
			(yyval.value)->type = objectidentifiervalue;
			(yyval.value)->u.objectidentifiervalue = (yyvsp[0].objid);
		}

    break;



      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYTERROR;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  yystos[*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}



void
yyerror (const char *s)
{
     lex_error_message ("%s\n", s);
}

static Type *
new_tag(int tagclass, int tagvalue, int tagenv, Type *oldtype)
{
    Type *t;
    if(oldtype->type == TTag && oldtype->tag.tagenv == TE_IMPLICIT) {
	t = oldtype;
	oldtype = oldtype->subtype; /* XXX */
    } else
	t = new_type (TTag);

    t->tag.tagclass = tagclass;
    t->tag.tagvalue = tagvalue;
    t->tag.tagenv = tagenv;
    t->subtype = oldtype;
    return t;
}

static struct objid *
new_objid(const char *label, int value)
{
    struct objid *s;
    s = emalloc(sizeof(*s));
    s->label = label;
    s->value = value;
    s->next = NULL;
    return s;
}

static void
add_oid_to_tail(struct objid *head, struct objid *tail)
{
    struct objid *o;
    o = head;
    while (o->next)
	o = o->next;
    o->next = tail;
}

static unsigned long idcounter;

static Type *
new_type (Typetype tt)
{
    Type *t = ecalloc(1, sizeof(*t));
    t->type = tt;
    t->id = idcounter++;
    return t;
}

static struct constraint_spec *
new_constraint_spec(enum ctype ct)
{
    struct constraint_spec *c = ecalloc(1, sizeof(*c));
    c->ctype = ct;
    return c;
}

static void fix_labels2(Type *t, const char *prefix);
static void fix_labels1(struct memhead *members, const char *prefix)
{
    Member *m;

    if(members == NULL)
	return;
    ASN1_TAILQ_FOREACH(m, members, members) {
	if (asprintf(&m->label, "%s_%s", prefix, m->gen_name) < 0)
	    errx(1, "malloc");
	if (m->label == NULL)
	    errx(1, "malloc");
	if(m->type != NULL)
	    fix_labels2(m->type, m->label);
    }
}

static void fix_labels2(Type *t, const char *prefix)
{
    for(; t; t = t->subtype)
	fix_labels1(t->members, prefix);
}

static void
fix_labels(Symbol *s)
{
    char *p = NULL;
    if (asprintf(&p, "choice_%s", s->gen_name) < 0 || p == NULL)
	errx(1, "malloc");
    fix_labels2(s->type, p);
    free(p);
}
