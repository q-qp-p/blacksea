# This module is never imported from the payload's graph. It must NEVER be
# vendored (module-level pruning). If discovery wrongly scanned it, the bogus
# import below would surface as an unresolved-import warning.
THIS_SHOULD_NOT_BE_BUNDLED = True

import this_module_definitely_does_not_exist  # noqa: F401,E402
