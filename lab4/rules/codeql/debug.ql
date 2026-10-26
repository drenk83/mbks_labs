/**
 * @name debug
 * @kind problem
 * @id cpp/lab4-debug
 */
import cpp

from IfStmt check, BinaryOperation lt
where
  check.getEnclosingFunction().hasName("wavlike_msadpcm_init") and
  lt = check.getCondition() and
  lt.getOperator() = "<"
select check, check.getLocation().getStartLine().toString() + " | " +
  lt.getLeftOperand().toString() + " | " + lt.getLeftOperand().getAQlClass()
