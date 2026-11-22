/**
 * @name MD5 o SHA-1 sin marcar como no criptográfico (todas las variantes)
 * @description Encuentra todas las formas de crear un hash débil (MD5 o SHA-1) en Python:
 *              hashlib.md5(), hashlib.sha1(), hashlib.new("md5"), alias de importación y la
 *              librería cryptography. Un hash débil solo es aceptable si se marca
 *              usedforsecurity=False (por ejemplo, datos de referencia que no protegen nada).
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision high
 * @id apkradar/py/weak-hash-variants
 * @tags security
 *       external/cwe/cwe-327
 *       external/cwe/cwe-328
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow

/** Nombres de algoritmos débiles. */
string weakAlgorithm() { result = ["md5", "sha1"] }

/** Variante 1: hashlib.md5(...) y hashlib.sha1(...), también con alias (from hashlib import md5). */
API::CallNode directCall() {
  result = API::moduleImport("hashlib").getMember(weakAlgorithm()).getACall()
}

/** Variante 2: hashlib.new("md5") o hashlib.new("SHA-1"), con el nombre en una constante. */
API::CallNode byNameCall() {
  result = API::moduleImport("hashlib").getMember("new").getACall() and
  exists(StringLiteral name |
    name = result.getArg(0).getALocalSource().asExpr() and
    name.getText().toLowerCase().replaceAll("-", "") = weakAlgorithm()
  )
}

/** Variante 3: cryptography.hazmat.primitives.hashes.MD5() y SHA1(). */
API::CallNode cryptographyCall() {
  result =
    API::moduleImport("cryptography")
        .getMember("hazmat")
        .getMember("primitives")
        .getMember("hashes")
        .getMember(["MD5", "SHA1"])
        .getACall()
}

/** La llamada está marcada con usedforsecurity=False (uso no criptográfico declarado). */
predicate markedNonSecurity(API::CallNode call) {
  exists(DataFlow::Node value |
    value = call.getArgByName("usedforsecurity") and
    value.getALocalSource().asExpr() instanceof False
  )
}

from API::CallNode call
where
  (call = directCall() or call = byNameCall()) and not markedNonSecurity(call)
  or
  call = cryptographyCall()
select call, "Hash débil (MD5/SHA-1) sin usedforsecurity=False: no lo uses para proteger datos."
