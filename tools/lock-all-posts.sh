#!/bin/bash
# Lock all posts that have locked: true in their front matter
# Usage: bash tools/lock-all-posts.sh

POSTS_DIR="_posts"
LOCKED_COUNT=0

echo "Scanning for locked posts..."

for post in "$POSTS_DIR"/*.md; do
    if [ -f "$post" ]; then
        if grep -q "^locked: true" "$post"; then
            echo "Processing: $(basename "$post")"
            bash tools/lock-post.sh "$post"
            ((LOCKED_COUNT++))
        fi
    fi
done

if [ $LOCKED_COUNT -eq 0 ]; then
    echo "No locked posts found."
else
    echo ""
    echo "✓ Processed $LOCKED_COUNT locked post(s)"
    echo "✓ Content stored in _locked_content/ (gitignored)"
    echo "✓ Post files updated (content removed from repository)"
fi

