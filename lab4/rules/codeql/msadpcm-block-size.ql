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

Expr unwrap(Expr e) {
  e instanceof ParenthesisExpr and result = unwrap(e.(ParenthesisExpr).getExpr())
  or
  not (e instanceof ParenthesisExpr) and result = e
}

predicate isAllocator(FunctionCall call) {
  call.getTarget().hasName("malloc") or
  call.getTarget().hasName("calloc")
}

Expr allocatorSizeArg(FunctionCall call) {
  isAllocator(call) and
  (
    call.getTarget().hasName("malloc") and result = call.getArgument(0)
    or
    call.getTarget().hasName("calloc") and result = call.getArgument(1)
  )
}

/** Аргумент аллокатора или правая часть присваивания этой переменной в той же функции. */
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

predicate mentions(Expr e, Variable v) { e.getAChild*() = v.getAnAccess() }

predicate isAddend(Expr size, Variable v) {
  exists(AddExpr add |
    add = size.getAChild*() and
    add.getAnOperand() = v.getAnAccess()
  )
}

predicate isFactor(Expr size, Variable v) {
  exists(MulExpr mul |
    mul = size.getAChild*() and
    mul.getAnOperand() = v.getAnAccess()
  )
}

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
  f = check.getEnclosingFunction() and
  weakProductCheck(check, blockVar) and
  exists(FunctionCall alloc, Expr arg |
    alloc.getEnclosingFunction() = f and
    arg = allocatorSizeArg(alloc) and
    size = resolvedSize(f, arg)
  ) and
  isAddend(size, blockVar) and
  isFactor(size, sampleVar) and
  sampleVar != blockVar and
  not mentions(unwrap(check.getCondition()).(BinaryOperation).getRightOperand(), sampleVar) and
  not exists(IfStmt other |
    other.getEnclosingFunction() = f and
    other != check and
    weakProductCheck(other, sampleVar)
  )
select check,
  "Слагаемое размера сравнивается с произведением, а другой множитель того же malloc/calloc так не ограничен"
