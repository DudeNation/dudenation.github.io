#!/bin/bash
# Unlock a post by restoring its content from private storage
# Usage: bash tools/unlock-post.sh _posts/your-post.md

LOCKED_DIR="_locked_content"
POST_FILE="$1"

if [ -z "$POST_FILE" ]; then
    echo "Usage: bash tools/unlock-post.sh _posts/your-post.md"
    exit 1
fi

if [ ! -f "$POST_FILE" ]; then
    echo "Error: File not found: $POST_FILE"
    exit 1
fi

# Extract post filename
POST_NAME=$(basename "$POST_FILE")

# Check if locked content exists
LOCKED_CONTENT="$LOCKED_DIR/${POST_NAME}.content"

if [ ! -f "$LOCKED_CONTENT" ]; then
    echo "Error: Locked content not found: $LOCKED_CONTENT"
    echo "The post may not have been locked, or content was already restored."
    exit 1
fi

# Find where front matter ends (second ---)
FRONT_MATTER_END=$(grep -n "^---$" "$POST_FILE" | sed -n '2p' | cut -d: -f1)

if [ -z "$FRONT_MATTER_END" ]; then
    echo "Error: Could not find end of front matter"
    exit 1
fi

# Extract front matter
head -n "$FRONT_MATTER_END" "$POST_FILE" > "/tmp/${POST_NAME}.frontmatter"

# Remove locked: true from front matter
sed -i.bak '/^locked: true$/d' "/tmp/${POST_NAME}.frontmatter"
rm -f "/tmp/${POST_NAME}.frontmatter.bak"

# Restore post with front matter + content
cat "/tmp/${POST_NAME}.frontmatter" > "$POST_FILE"
echo "" >> "$POST_FILE"
cat "$LOCKED_CONTENT" >> "$POST_FILE"

# Remove the locked content file (optional - you can keep it as backup)
# rm -f "$LOCKED_CONTENT"

echo "✓ Post unlocked: Content restored from $LOCKED_CONTENT"
echo "✓ Removed 'locked: true' from front matter"
echo "✓ Post is now ready to publish"

rm -f "/tmp/${POST_NAME}.frontmatter"

