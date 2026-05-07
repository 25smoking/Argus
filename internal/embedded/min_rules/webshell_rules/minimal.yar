rule Argus_Minimal_Webshell_Keywords {
  strings:
    $a = "eval($_POST" nocase
    $b = "system($_GET" nocase
    $c = "Runtime.getRuntime().exec" nocase
  condition:
    any of them
}
