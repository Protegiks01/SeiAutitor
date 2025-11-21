import json
import os
from audit import Deepwiki
from questions import questions


def load_processed_questions():
    """Load processed questions from both collections and reversed_collections JSON files"""
    processed = set()

    for filename in ["collections.json", "reversed_collections.json"]:
        if not os.path.exists(filename):
            continue
        try:
            with open(filename, "r") as f:
                data = json.load(f)
                processed.update(item.get("question", "") for item in data)
        except Exception as e:
            print(f"Error loading {filename}: {e}")

    return processed

try:
    processed = load_processed_questions()
    total = len(questions)
    skipped = 0
    processed_count = 0

    print(f"Total questions: {total}")
    print(f"Already processed: {len(processed)}")

    counter = 0
    for i, question in enumerate(questions):
        # Skip if already processed
        if question in processed:
            skipped += 1
            print(f"[{i + 1}/{total}] Skipping (already processed): {question[:50]}...")
            continue

        print(f"[{i + 1}/{total}] Processing: {question[:50]}...")
        bot = Deepwiki(teardown=True)
        bot.ask_question(question, is_reversed=False)
        processed_count += 1

        counter += 1
        if counter >= 25:
            break

    print(f"\n=== Summary ===")
    print(f"Skipped: {skipped}")
    print(f"Newly processed: {processed_count}")
    print(f"Total: {total}")

except Exception as e:
    print(f"Error: {e}")



