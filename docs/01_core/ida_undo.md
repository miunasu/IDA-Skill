# ida_undo

## Functions Overview

- `create_undo_point(*args) -> bool`: Create a new restore point. The user can undo to this point in the future.
- `get_undo_action_label() -> str`: Get the label of the action that will be undone. This function returns the text that can be displayed in the undo menu
- `get_redo_action_label() -> str`: Get the label of the action that will be redone. This function returns the text that can be displayed in the redo menu
- `perform_undo() -> bool`: Perform undo.
- `perform_redo() -> bool`: Perform redo.