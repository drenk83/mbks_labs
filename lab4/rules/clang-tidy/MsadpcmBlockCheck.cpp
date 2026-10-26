// Правило CodeChecker: checker для clang-tidy, который ищет слабую проверку
// размера блока MS ADPCM в libsndfile 1.0.30 (CVE-2021-3246).
//
// Правило срабатывает на условие
//     if (blockalign < 7 * psf->sf.channels)
// внутри wavlike_msadpcm_init. В 1.1.0 это условие заменено на проверку
// samplesperblock и дополнительную проверку 2 * blockalign, поэтому
// на исправленной версии правило молчит.

#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang-tidy/ClangTidy.h"
#include "clang-tidy/ClangTidyCheck.h"
#include "clang-tidy/ClangTidyModule.h"

using namespace clang;
using namespace clang::tidy;
using namespace clang::ast_matchers;

namespace {

class MsadpcmBlockCheck : public ClangTidyCheck {
public:
  MsadpcmBlockCheck(StringRef Name, ClangTidyContext *Context)
      : ClangTidyCheck(Name, Context) {}

  void registerMatchers(MatchFinder *Finder) override {
    Finder->addMatcher(
        ifStmt(
            hasAncestor(
                functionDecl(hasName("wavlike_msadpcm_init"))),
            hasCondition(binaryOperator(
                hasOperatorName("<"),
                hasLHS(ignoringImplicit(
                    declRefExpr(to(varDecl(hasName("blockalign")))))),
                hasRHS(ignoringImplicit(binaryOperator(
                    hasOperatorName("*"),
                    hasLHS(integerLiteral(equals(7)))))))))
            .bind("weak-check"),
        this);
  }

  void check(const MatchFinder::MatchResult &Result) override {
    const auto *Check = Result.Nodes.getNodeAs<IfStmt>("weak-check");
    if (Check == nullptr)
      return;

    diag(Check->getIfLoc(),
         "MS ADPCM: blockalign проверяется вместо samplesperblock; "
         "возможен выход за границу буфера (CVE-2021-3246)");
  }
};

class Lab4Module : public ClangTidyModule {
public:
  void addCheckFactories(ClangTidyCheckFactories &CheckFactories) override {
    CheckFactories.registerCheck<MsadpcmBlockCheck>(
        "lab4-msadpcm-block-size");
  }
};

} // namespace

static ClangTidyModuleRegistry::Add<Lab4Module> Lab4ModuleRegistration(
    "lab4-module", "Правила лабораторной работы № 4");
