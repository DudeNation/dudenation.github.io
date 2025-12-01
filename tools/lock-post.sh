#!/bin/bash
# Lock a post by extracting its content to a private location
# Usage: bash tools/lock-post.sh _posts/your-post.md

LOCKED_DIR="_locked_content"
POST_FILE="$1"

if [ -z "$POST_FILE" ]; then
    echo "Usage: bash tools/lock-post.sh _posts/your-post.md"
    exit 1
fi

if [ ! -f "$POST_FILE" ]; then
    echo "Error: File not found: $POST_FILE"
    exit 1
fi

# Create locked content directory if it doesn't exist
mkdir -p "$LOCKED_DIR"

# Extract post filename
POST_NAME=$(basename "$POST_FILE")

# Check if already locked
if grep -q "^locked: true" "$POST_FILE"; then
    echo "Post is already locked. Extracting content..."
    
    # Find where front matter ends (second ---)
    FRONT_MATTER_END=$(grep -n "^---$" "$POST_FILE" | sed -n '2p' | cut -d: -f1)
    
    if [ -z "$FRONT_MATTER_END" ]; then
        echo "Error: Could not find end of front matter"
        exit 1
    fi
    
    # Extract front matter (lines 1 to FRONT_MATTER_END)
    head -n "$FRONT_MATTER_END" "$POST_FILE" > "/tmp/${POST_NAME}.frontmatter"
    
    # Extract content (lines after FRONT_MATTER_END)
    tail -n +$((FRONT_MATTER_END + 1)) "$POST_FILE" > "$LOCKED_DIR/${POST_NAME}.content"
    
    # Check if content was already extracted
    if [ -f "$LOCKED_DIR/${POST_NAME}.content" ] && [ -s "$LOCKED_DIR/${POST_NAME}.content" ]; then
        # Replace post file with front matter only + placeholder
        cat "/tmp/${POST_NAME}.frontmatter" > "$POST_FILE"
        echo "" >> "$POST_FILE"
        echo "<!-- Content stored privately in _locked_content/${POST_NAME}.content -->" >> "$POST_FILE"
        echo "<!-- This content will be restored when post is unlocked -->" >> "$POST_FILE"
        
        echo "✓ Post locked: Content extracted to $LOCKED_DIR/${POST_NAME}.content"
        echo "✓ Post file updated (content removed from repository)"
    else
        echo "Error: Failed to extract content"
        exit 1
    fi
    
    rm -f "/tmp/${POST_NAME}.frontmatter"
else
    echo "Post is not marked as locked. Add 'locked: true' to front matter first."
    exit 1
fi

