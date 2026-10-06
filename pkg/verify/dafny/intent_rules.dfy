// pkg/verify/dafny/intent_rules.dfy

datatype Verdict = VERDICT_PASS | VERDICT_ABORT

datatype ActionNode = ActionNode(id: int, targetSubnet: int, writePrivilege: bool)

predicate IsValidSubnet(subnet: int) {
  subnet >= 1000 && subnet <= 9999
}

predicate SystemInvariant(node: ActionNode) {
  node.writePrivilege ==> IsValidSubnet(node.targetSubnet)
}

method CompileIntentNode(node: ActionNode) returns (v: Verdict)
  ensures v == VERDICT_PASS ==> SystemInvariant(node)
{
  if node.writePrivilege && (node.targetSubnet < 1000 || node.targetSubnet > 9999) {
    return VERDICT_ABORT;
  } else {
    return VERDICT_PASS;
  }
}

method VerifyGraphArray(graph: array?<ActionNode>) returns (v: Verdict)
  requires graph != null
  ensures v == VERDICT_PASS ==> forall i :: 0 <= i < graph.Length ==> SystemInvariant(graph[i])
{
  var idx := 0;
  while idx < graph.Length
    invariant 0 <= idx <= graph.Length
    invariant forall k :: 0 <= k < idx ==> SystemInvariant(graph[k])
  {
    var node_verdict := CompileIntentNode(graph[idx]);
    if node_verdict == VERDICT_ABORT {
      return VERDICT_ABORT;
    }
    idx := idx + 1;
  }
  return VERDICT_PASS;
}
