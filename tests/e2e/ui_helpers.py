"""Shared Playwright helpers for driving PrimeVue widgets.

PrimeVue components are custom widgets, not native HTML controls, so
``page.select_option`` (which only works on a real ``<select>``) cannot be
used. A PrimeVue ``Select`` exposes its root element via the ``id`` prop; we
open it with a click and pick the option from the teleported overlay by its
ARIA ``option`` role.
"""


def pv_select(page, select_id, *, label=None, index=None, exact=True):
    """Open the PrimeVue Select ``#select_id`` and choose an option.

    Pass ``label`` to match an option by its visible text (``exact`` controls
    substring vs. exact matching) or ``index`` to pick the n-th option.
    """
    page.click(f"#{select_id}")
    if index is not None:
        option = page.get_by_role("option").nth(index)
    else:
        option = page.get_by_role("option", name=label, exact=exact).first
    option.wait_for(state="visible")
    option.click()
