// Слабая проверка размера перед malloc/calloc (CVE-2021-3246) без имён функции и полей.
//
// Что ищем (форма кода):
//   if (B < ... * ...)                 // B — идентификатор слева от "<"
//   ...
//   $SZ = ... + B + ... * S;           // B — слагаемое размера, S — множитель
//   ... = malloc($SZ) / calloc($N, $SZ);
// при этом S в этой же функции сам не сравнивается с произведением.
// Литерал 7 не требуется.
//
// В libsndfile 1.0.30: B = blockalign, S = samplesperblock,
// проверка находится в src/ms_adpcm.c:131.
// В 1.1.0 слева стоит samplesperblock: это множитель, а не слагаемое,
// поэтому скрипт молчит.
//
// Ожидаемый результат: 1.0.30 — 1 находка (ms_adpcm.c:131),
// 1.1.0 — 0, fixture — 2.

import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, Call, Identifier, Method}

@main def main(inputPath: String, outFile: String) = {
  importCode.c(inputPath)

  // Имя оператора, если узел является вызовом: "<operator>.addition" и т. п.
  // У не-вызовов пустая строка, чтобы match ниже не падал.
  def op(n: AstNode): String = n match {
    case c: Call => c.name
    case _       => ""
  }

  // Все идентификаторы в поддереве. По ним видно, какие переменные
  // участвуют в правой части сравнения.
  def idents(n: AstNode): Set[String] = {
    val here = n match {
      case i: Identifier => Set(i.code)
      case _             => Set.empty[String]
    }
    n.astChildren.foldLeft(here)((acc, child) => acc ++ idents(child))
  }

  // Прямые идентификаторы-операнды сложения и умножения внутри выражения.
  // Рекурсия нужна потому, что размер — дерево: sizeof(...) + B + 3 * C * S.
  // addends — слагаемые, factors — множители.
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

  // if (B < ... * ...): возвращает имя B и идентификаторы правой части.
  // kids(1) — второй ребёнок условия, то есть правая часть сравнения;
  // она должна быть умножением.
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
  // Фильтр arg.code != call.code отбрасывает сам вызов, оставляя аргументы.
  def allocArgCodes(method: Method): List[String] =
    method.call
      .name("(malloc|calloc)")
      .flatMap { call =>
        call.argument.l.collect {
          case arg if arg.code != call.code => arg.code
        }
      }
      .l

  // Выражение размера: сам аргумент аллокатора и правая часть присваивания,
  // если аргумент — переменная. В libsndfile в calloc идёт pmssize,
  // а интересные blockalign и samplesperblock — в её присваивании.
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

  // Находка: имя слева от "<" есть среди слагаемых размера,
  // а какой-то множитель того же размера нигде не проверен.
  val hits = cpg.controlStructure
    .controlStructureType(ControlStructureTypes.IF)
    .flatMap { cs =>
      val method = cs.method
      cs.condition.l.flatMap { cond =>
        weakCheck(cond).toList.flatMap { case (blockName, rightIds) =>
          // Все имена, которые в этом методе уже стоят слева от "X < ... * ...":
          // такой множитель ограничен, это случай исправленного 1.1.0.
          val guarded = method.controlStructure
            .controlStructureType(ControlStructureTypes.IF)
            .condition
            .flatMap(c => weakCheck(c).toList)
            .map(_._1)
            .toSet
          val matched = allocArgCodes(method).exists { argCode =>
            sizeExprs(method, argCode).exists { root =>
              val (addends, factors) = operands(root)
              // Кандидаты в непроверенные множители:
              //   factors      — все множители размера,
              //   -- addends   — кроме слагаемых,
              //   - blockName  — кроме B,
              //   -- rightIds  — кроме переменных с правой стороны сравнения
              //                  (обычно channels: его проверять не нужно).
              val samples = factors -- addends - blockName -- rightIds
              addends.contains(blockName) && samples.exists(sample => !guarded.contains(sample))
            }
          }
          if (!matched) Nil
          else {
            // Печатаем место самого if — так находка совпадает с ms_adpcm.c:131.
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
