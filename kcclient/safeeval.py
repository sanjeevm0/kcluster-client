import ast
import traceback

allowed = ['int', 'str', 'min', 'max', 'range', 'list', 'filter', 'math.sin', 'math.cos']

def getFuncName(v):
    if type(v)==ast.Name:
        return v.id
    elif type(v)==ast.Attribute:
        return getFuncName(v.value) + "." + v.attr

def isSafeExpr(x, msgs, allowVars):
    tp = type(x)
    if tp==ast.Assign:
        if not isSafeExpr(x.value, msgs, allowVars):
            return False
        for t in x.targets:
            if not isSafeExpr(t, msgs, allowVars):
                return False
        return True
    elif tp==ast.Constant:
        return True
    elif tp==ast.Expr:
        return isSafeExpr(x.value, msgs, allowVars)
    elif tp==ast.BinOp:
        # op does not matter
        if not isSafeExpr(x.left, msgs, allowVars):
            return False
        if not isSafeExpr(x.right, msgs, allowVars):
            return False
        return True
    elif tp==ast.UnaryOp:
        return isSafeExpr(x.operand, msgs, allowVars)
    elif tp==ast.Name:
        if not allowVars:
            msgs.append("Variables are not allowed")
        return allowVars
    elif tp==ast.Num:
        return True
    elif tp==ast.Str:
        return True
    elif tp==ast.Subscript:
        if not isSafeExpr(x.slice, msgs, allowVars):
            return False
        if not isSafeExpr(x.value, msgs, allowVars):
            return False
        return True
    elif tp==ast.Index:
        return isSafeExpr(x.value, msgs, allowVars)
    elif tp==ast.Dict:
        for kv in (x.keys + x.values):
            if not isSafeExpr(kv, msgs, allowVars):
                return False
        return True
    elif tp==ast.List:
        for e in x.elts:
            if not isSafeExpr(e, msgs, allowVars):
                return False
        return True
    elif tp==ast.Call:
        fnName = getFuncName(x.func)
        if fnName not in allowed:
            msgs.append("{0} not allowed function".format(fnName))
            return False
        for arg in x.args:
            if not isSafeExpr(arg, msgs, allowVars):
                return False
        return True
    elif tp==ast.ListComp:
        if not isSafeExpr(x.elt, msgs, allowVars):
            return False
        for g in x.generators:
            if not isSafeExpr(g, msgs, allowVars):
                return False
        return True
    elif tp==ast.comprehension:
        if not isSafeExpr(x.iter, msgs, allowVars):
            return False
        if not isSafeExpr(x.target, msgs, allowVars):
            return False
        return True
    elif tp==ast.Lambda:
        if not isSafeExpr(x.args, msgs, allowVars):
            return False
        if not isSafeExpr(x.body, msgs, allowVars):
            return False
        return True
    elif tp==ast.arguments:
        if x.kwarg is not None or x.vararg is not None:
            msgs.append("Non None kwarg or vararg")
            return False
        for a in (x.args + x.defaults + x.kw_defaults + x.kwonlyargs):
            if not isSafeExpr(a, msgs, allowVars):
                return False
        return True
    elif tp==ast.arg:
        return True
    elif tp==ast.Compare:
        if not isSafeExpr(x.left, msgs, allowVars):
            return False
        for c in x.comparators:
            if not isSafeExpr(c, msgs, allowVars):
                return False
        # x.ops is okay
        return True
    else:
        msgs.append("Don't know type {0}".format(tp))
        return False

cache = {}

def isSafe(x, allowVars=False):
    if x in cache:
        ret, msgs, allowVarsCache = cache[x]
        if allowVars==allowVarsCache:
            return ret, msgs

    try:
        msgs = []
        ret = isSafeExpr(ast.parse(x).body[0], msgs, allowVars)
    except Exception as ex:
        msgs = ["{0}: {1}".format(ex, traceback.format_exc())]
        ret = False
    cache[x] = (ret, msgs, allowVars)
    return ret, msgs

