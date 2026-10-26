/**
 * @name CVE-2021-3246: недостаточная проверка размера блока MS ADPCM
 * @description В wavlike_msadpcm_init проверяется только blockalign,
 *              но не samplesperblock. Из-за этого msadpcm_decode_block
 *              может записать больше сэмплов, чем выделено в calloc.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.8
 * @id cpp/lab4-msadpcm-block-size
 * @tags security
 *       external/cwe/cwe-787
 *       external/cwe/cwe-122
 */

import cpp

from IfStmt check, BinaryOperation lt
where
  check.getEnclosingFunction().hasName("wavlike_msadpcm_init") and
  lt = check.getCondition() and
  lt.getOperator() = "<" and
  lt.getLeftOperand().toString() = "blockalign"
select check,
  "Проверка размера блока MS ADPCM использует blockalign и не ограничивает samplesperblock (CVE-2021-3246)"
