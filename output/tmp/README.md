# Temporary output packages

`output/tmp/` holds review packages that are deliberately outside the production application. Nothing here is imported by the production build or is ready to ship.

## Required cleanup after a direction is chosen

1. Record the selected direction and its rationale in the relevant production task or pull request.
2. Implement only the approved production changes in their proper source locations; do not promote this package wholesale.
3. Retain only the evidence or provenance needed for that implementation.
4. Delete `output/tmp/platform-visual-directions/` in a dedicated cleanup commit. Remove this README too if it is the last temporary package.
