NOTES="$TMPDIR/notes.md"; [ -f "$NOTES" ] || NOTES="./RELEASE_NOTES_TMP.md"
gh release create v0.7.1 --repo roshcompanylabs/llm-stream-guardrails --title "v0.7.1" --notes-file "$NOTES" 2>&1 | sed 's/^/   /'
rm -f ./RELEASE_NOTES_TMP.md
