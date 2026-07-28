def normalize(value):
    return value.strip().lower()


def unused_helper(value):
    # Never referenced anywhere in the SDK or payload: a target for
    # --experimental-treeshake. Present to prove tree-shaking can drop it.
    return value * 999
