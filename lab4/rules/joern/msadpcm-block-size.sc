// Ищет слабую проверку размера блока MS ADPCM (CVE-2021-3246):
// внутри wavlike_msadpcm_init условие вида `blockalign < 7 * ...`.
// В libsndfile 1.1.0 слева стоит samplesperblock или `2 * blockalign`,
// поэтому правило на исправленной версии молчит.

@main def main(inputPath: String, outFile: String) = {
  importCode.c(inputPath)

  val hits = cpg.method
    .nameExact("wavlike_msadpcm_init")
    .controlStructure
    .controlStructureType(ControlStructureTypes.IF)
    .filter { cs =>
      cs.condition.l.exists { cond =>
        val kids = cond.astChildren.l
        kids.length >= 2 &&
        kids.head.code == "blockalign" &&
        kids(1).code.startsWith("7 *")
      }
    }
    .map { cs =>
      val file = cs.file.name.l.headOption.getOrElse("?")
      val line = cs.lineNumber.map(_.toString).getOrElse("?")
      val code = cs.condition.code.l.headOption.getOrElse(cs.code)
      s"$file:$line: $code"
    }
    .l
    .distinct
    .sorted

  val text = s"находок: ${hits.size}\n" + hits.map(h => s"$h\n").mkString
  java.nio.file.Files.writeString(java.nio.file.Paths.get(outFile), text)
  println(text)
}
