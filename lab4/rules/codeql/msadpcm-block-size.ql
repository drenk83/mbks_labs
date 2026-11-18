/**
 * @name CVE-2021-3246: слабая проверка преамбулы перед размером буфера
 * @description В одной функции размер malloc/calloc складывается из переменной B
 *              и произведения с другой переменной S. B сравнивается с произведением,
 *              а S так не ограничивается. Литерал 7 не требуется. Имена функции
 *              и полей не заданы.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.8
 * @id cpp/lab4-msadpcm-block-size
 * @tags security
 *       external/cwe/cwe-787
 *       external/cwe/cwe-122
 */

import cpp

/** Снимает скобки вокруг выражения. */
Expr unwrap(Expr e) {
  e instanceof ParenthesisExpr and result = unwrap(e.(ParenthesisExpr).getExpr())
  or
  not e instanceof ParenthesisExpr and result = e
}

/** Прямой вызов malloc или calloc; обёртки вроде psf_calloc не раскрываются. */
predicate isAllocator(FunctionCall call) {
  call.getTarget().hasName("malloc") or
  call.getTarget().hasName("calloc")
}

/** Аргумент размера: у malloc первый, у calloc второй (size, а не count). */
Expr allocatorSizeArg(FunctionCall call) {
  isAllocator(call) and
  (
    call.getTarget().hasName("malloc") and result = call.getArgument(0)
    or
    call.getTarget().hasName("calloc") and result = call.getArgument(1)
  )
}

/** Размер — аргумент аллокатора или правая часть присваивания этой переменной в той же функции (например, pmssize). */
Expr resolvedSize(Function f, Expr arg) {
  arg.getEnclosingFunction() = f and
  (
    result = arg
    or
    exists(Variable v, AssignExpr assign |
      arg.(VariableAccess).getTarget() = v and
      assign.getEnclosingFunction() = f and
      assign.getLValue().(VariableAccess).getTarget() = v and
      result = assign.getRValue()
    )
  )
}

/** Переменная встречается где угодно внутри выражения (на любой глубине AST). */
predicate mentions(Expr e, Variable v) { e.getAChild*() = v.getAnAccess() }

/** Переменная — операнд сложения в размере (поиск на любой глубине AST). */
predicate isAddend(Expr size, Variable v) {
  exists(AddExpr add |
    add = size.getAChild*() and
    add.getAnOperand() = v.getAnAccess()
  )
}

/** Переменная — операнд умножения в размере (поиск на любой глубине AST). */
predicate isFactor(Expr size, Variable v) {
  exists(MulExpr mul |
    mul = size.getAChild*() and
    mul.getAnOperand() = v.getAnAccess()
  )
}

/** if с оператором <: слева переменная, справа умножение (только строгий <). */
predicate weakProductCheck(IfStmt check, Variable blockVar) {
  exists(BinaryOperation cmp |
    cmp = unwrap(check.getCondition()) and
    cmp.getOperator() = "<" and
    blockVar = unwrap(cmp.getLeftOperand()).(VariableAccess).getTarget() and
    unwrap(cmp.getRightOperand()) instanceof MulExpr
  )
}

from Function f, IfStmt check, Variable blockVar, Variable sampleVar, Expr size
where
  // 1) проверка и аллокатор должны быть в одной функции
  f = check.getEnclosingFunction() and
  // 2) if (B < ... * ...): слева B, справа умножение
  weakProductCheck(check, blockVar) and
  // 3) в функции есть malloc/calloc, а size — его аргумент размера
  exists(FunctionCall alloc, Expr arg |
    alloc.getEnclosingFunction() = f and
    arg = allocatorSizeArg(alloc) and
    size = resolvedSize(f, arg)
  ) and
  // 4) B — слагаемое размера
  isAddend(size, blockVar) and
  // 5) S — множитель того же размера
  isFactor(size, sampleVar) and
  // 6) B и S — разные переменные, S не стоит справа от сравнения
  sampleVar != blockVar and
  not mentions(unwrap(check.getCondition()).(BinaryOperation).getRightOperand(), sampleVar) and
  // 7) S сам не ограничен сравнением с произведением (как в 1.1.0)
  not exists(IfStmt other |
    other.getEnclosingFunction() = f and
    other != check and
    weakProductCheck(other, sampleVar)
  )
select check,
  "Слагаемое размера сравнивается с произведением, а другой множитель того же malloc/calloc так не ограничен"
