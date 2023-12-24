{ ... }: {
  deployment.keys.secret-foo.text = builtins.extraBuiltins.pass "secret-foo";
}
