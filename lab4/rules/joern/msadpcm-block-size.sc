// Слабая проверка размера перед malloc/calloc (CVE-2021-3246) без имён функции и полей.
// В одной функции: if (B < ... * ...), слева идентификатор B. Литерал 7 не требуется.
// B — слагаемое размера malloc/calloc, напрямую или через присваивание.
// Другой идентификатор S — множитель того же размера и сам так не сравнивается.
// В 1.1.0 слева стоит samplesperblock: это множитель, а не слагаемое, поэтому тишина.

import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, Call, Identifier, Method}

@main def main(inputPath: String, outFile: String) = {
  importCode.c(inputPath)

  // Имя оператора, если узел является вызовом.
  def op(n: AstNode): String = n match {
    case c: Call => c.name
    case _       => ""
  }

  // Все идентификаторы в поддереве.
  def idents(n: AstNode): Set[String] = {
    val here = n match {
      case i: Identifier => Set(i.code)
      case _             => Set.empty[String]
    }
    n.astChildren.foldLeft(here)((acc, child) => acc ++ idents(child))
  }

  // Прямые идентификаторы-операнды сложения и умножения внутри выражения.
  def operands(n: AstNode): (Set[String], Set[String]) = {
    val own = op(n) match {
      case "<operator>.addition" =>
        (n.astChildren.collect { case i: Identifier => i.code }.toSet, Set.empty[String])
      case "<operator>.multiplication" =>
        (Set.empty[String], n.astChildren.collect { case i: Identifier => i.code }.toSet)
      case _ =>
        (Set.empty[String], Set.empty[String])
    }
    n.astChildren.foldLeft(own) { case ((add, mul), child) =>
      val (a2, m2) = operands(child)
      (add ++ a2, mul ++ m2)
    }
  }

  // if (B < ... * ...): имя B и идентификаторы правой части.
  def weakCheck(cond: AstNode): Option[(String, Set[String])] = {
    val kids = cond.astChildren.l
    if (kids.length < 2) None
    else
      kids.head match {
        case left: Identifier if op(kids(1)) == "<operator>.multiplication" =>
          Some((left.code, idents(kids(1))))
        case _ => None
      }
  }

  // Тексты аргументов malloc и calloc в методе.
  def allocArgCodes(method: Method): List[String] =
    method.call
      .name("(malloc|calloc)")
      .flatMap { call =>
        call.argument.l.collect {
          case arg if arg.code != call.code => arg.code
        }
      }
      .l

  // Выражение размера: сам аргумент и правая часть присваивания, если аргумент — переменная.
  def sizeExprs(method: Method, argCode: String): List[AstNode] = {
    val assigned = method.call.nameExact("<operator>.assignment").flatMap { assign =>
      val kids = assign.astChildren.l
      if (kids.length >= 2 && kids.head.code == argCode) List(kids(1)) else Nil
    }.l
    val direct = method.call.name("(malloc|calloc)").flatMap { call =>
      call.argument.l.collect {
        case arg if arg.code == argCode => arg
      }
    }.l
    (assigned ++ direct).distinct
  }

  // Находка, если имя слева есть среди слагаемых, а какой-то множитель так не проверен.
  val hits = cpg.controlStructure
    .controlStructureType(ControlStructureTypes.IF)
    .flatMap { cs =>
      val method = cs.method
      cs.condition.l.flatMap { cond =>
        weakCheck(cond).toList.flatMap { case (blockName, rightIds) =>
          val guarded = method.controlStructure
            .controlStructureType(ControlStructureTypes.IF)
            .condition
            .flatMap(c => weakCheck(c).toList)
            .map(_._1)
            .toSet
          val matched = allocArgCodes(method).exists { argCode =>
            sizeExprs(method, argCode).exists { root =>
              val (addends, factors) = operands(root)
              val samples = factors -- addends - blockName -- rightIds
              addends.contains(blockName) && samples.exists(sample => !guarded.contains(sample))
            }
          }
          if (!matched) Nil
          else {
            val file = cs.file.name.l.headOption.getOrElse("?")
            val line = cs.lineNumber.map(_.toString).getOrElse("?")
            List(s"$file:$line: ${cond.code}")
          }
        }
      }
    }
    .l
    .distinct
    .sorted

  val text = s"находок: ${hits.size}\n" + hits.map(h => s"$h\n").mkString
  java.nio.file.Files.writeString(java.nio.file.Paths.get(outFile), text)
  println(text)
}
