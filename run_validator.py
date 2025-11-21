import json
import os
from pathlib import Path
from audit_validation import Validator


def load_processed_reports():
    """Load the set of already processed audit files from validated.json"""
    if not os.path.exists("validated.json"):
        return set()

    try:
        with open("validated.json", "r") as f:
            data = json.load(f)
            # Return a set of processed filenames
            return {item.get("filename", "") for item in data if "filename" in item}
    except Exception as e:
        print(f"Error loading collections: {e}")
        return set()


def get_audits_reports():
    # Get all .md files from the audits directory
    audits_dir = Path("audits")
    return sorted(audits_dir.glob("*.md"))


def get_remaining_count():
    """
    Returns the total number of audit files that haven't been validated yet.

    :return: Tuple of (remaining_count, total_count, processed_count)
    """
    try:
        # Get all audit files
        audit_files = get_audits_reports()
        total_count = len(audit_files)

        # Get processed files
        processed_files = load_processed_reports()
        processed_count = len(processed_files)

        # Calculate remaining
        remaining_count = total_count - processed_count

        return remaining_count

    except Exception as e:
        print(f"Error getting remaining count: {e}")
        return 0


def main():
    try:
        # Get all audit files
        audit_files = get_audits_reports()
        total = len(audit_files)
        processed_files = load_processed_reports()

        print(f"Found {total} audit files to process")
        print(f"Already processed: {len(processed_files)}")

        processed_count = 0
        skipped_count = 0
        counter = 0

        for i, audit_file in enumerate(audit_files, 1):
            if audit_file.name in processed_files:
                print(f"[{i}/{total}] Skipping (already processed): {audit_file.name}")
                skipped_count += 1
                continue

            print(f"\n[{i}/{total}] Processing: {audit_file.name}")

            try:
                with open(audit_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Initialize the validator and process the content
                bot = Validator(teardown=True)
                print(f"Processing content from {audit_file.name}...")

                # Assuming bot.ask_question() is what processes the content
                # You might want to pass the filename as well
                bot.ask_question(audit_file.name, content)

                # Add to processed files
                processed_files.add(audit_file.name)
                processed_count += 1

                counter += 1
                if counter >= 25:
                    break

            except Exception as e:
                print(f"Error processing {audit_file.name}: {str(e)}")
                continue

        print(f"\n=== Summary ===")
        print(f"Total files: {total}")
        print(f"Processed: {processed_count}")
        print(f"Skipped: {skipped_count}")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == '__main__':
    main()