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

/*
 * Что ищет запрос — форму кода, а не конкретную функцию:
 *
 *   $SZ = ... + B + ... * S;      // B — слагаемое размера, S — множитель
 *   if (B < K * C) { ... }        // B проверен снизу
 *   p = malloc($SZ);              // или calloc(n, $SZ)
 *
 * Находка выдаётся, только если S в этой же функции нигде не сравнивается
 * с произведением (нет if (S < K2 * C2)). Имена B, S, C и множитель K
 * произвольны: литерал 7 в правиле не зашит.
 *
 * Пример из libsndfile 1.0.30 (src/ms_adpcm.c:131):
 *   if (blockalign < 7 * psf->sf.channels) ...
 *   pmssize = sizeof(...) + blockalign + 3 * channels * samplesperblock;
 *   calloc(1, pmssize);
 * Здесь B = blockalign, S = samplesperblock.
 * В 1.1.0 сравнение перенесено на samplesperblock, то есть на S,
 * поэтому запрос молчит: 1 находка на 1.0.30, 0 на 1.1.0.
 *
 * Ожидаемый результат: 1.0.30 — 1, 1.1.0 — 0, fixture — 2.
 */

import cpp

/**
 * Снимает скобки вокруг выражения.
 * if ((blockalign) < (7 * channels)) разбирается так же, как без скобок.
 */
Expr unwrap(Expr e) {
  e instanceof ParenthesisExpr and result = unwrap(e.(ParenthesisExpr).getExpr())
  or
  not (e instanceof ParenthesisExpr) and result = e
}

/**
 * Прямой вызов malloc или calloc.
 * Обёртки вроде psf_calloc не раскрываются: смотрим только имя цели вызова.
 */
predicate isAllocator(FunctionCall call) {
  call.getTarget().hasName("malloc") or
  call.getTarget().hasName("calloc")
}

/**
 * Аргумент с размером: у malloc первый, у calloc второй.
 * calloc(count, size) выделяет count * size байт, поэтому нужен именно size.
 */
Expr allocatorSizeArg(FunctionCall call) {
  isAllocator(call) and
  (
    call.getTarget().hasName("malloc") and result = call.getArgument(0)
    or
    call.getTarget().hasName("calloc") and result = call.getArgument(1)
  )
}

/**
 * Аргумент аллокатора или правая часть присваивания этой переменной
 * в той же функции.
 * В libsndfile в calloc передаётся уже посчитанная переменная pmssize,
 * поэтому без перехода к присваиванию запрос не увидел бы blockalign
 * и samplesperblock.
 */
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

/**
 * Переменная является операндом сложения в размере.
 * Поиск рекурсивный: sizeof(...) + blockalign + 3 * channels * samplesperblock
 * содержит сложение и на верхнем уровне, и внутри произведения.
 */
predicate isAddend(Expr size, Variable v) {
  exists(AddExpr add |
    add = size.getAChild*() and
    add.getAnOperand() = v.getAnAccess()
  )
}

/**
 * Переменная является операндом умножения в размере.
 * Для того же размера samplesperblock — множитель в 3 * channels * samplesperblock.
 */
predicate isFactor(Expr size, Variable v) {
  exists(MulExpr mul |
    mul = size.getAChild*() and
    mul.getAnOperand() = v.getAnAccess()
  )
}

/**
 * if с оператором <: слева переменная, справа умножение.
 * Учитывается только строгий <; <= и произвольные выражения справа не подходят.
 */
predicate weakProductCheck(IfStmt check, Variable blockVar) {
  exists(BinaryOperation cmp |
    cmp = unwrap(check.getCondition()) and
    cmp.getOperator() = "<" and
    blockVar = unwrap(cmp.getLeftOperand()).(VariableAccess).getTarget() and
    unwrap(cmp.getRightOperand()) instanceof MulExpr
  )
}

/**
 * В одной функции слагаемое размера сравнивается с произведением,
 * а множитель так не ограничен.
 *
 * Условия по порядку:
 *   1) проверка и аллокатор находятся в одной функции;
 *   2) проверка имеет вид B < ... * ...;
 *   3) в функции есть malloc/calloc, размер которого — size;
 *   4) B входит в size слагаемым;
 *   5) S входит в size множителем;
 *   6) S — не та же переменная, что B, и не стоит справа от сравнения
 *      (обычно справа channels — его проверять не нужно);
 *   7) S сам нигде не сравнивается с произведением — это и отсекает 1.1.0.
 */
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
