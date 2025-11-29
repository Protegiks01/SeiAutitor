import os
import shutil
import json


def clean_up():
    """
    Clean up the project by:
    1. Deleting all files in audits folder
    2. Moving all files from validated folder to audits folder
    3. Emptying collections.json, validated.json, and reversed_collections.json
    """
    try:
        # Step 1: Delete all files in audits folder
        audits_dir = "audits"
        if os.path.exists(audits_dir):
            for filename in os.listdir(audits_dir):
                file_path = os.path.join(audits_dir, filename)
                if os.path.isfile(file_path):
                    os.remove(file_path)
                    print(f"Deleted: {file_path}")
            print(f"Cleaned {audits_dir} folder")
        else:
            os.makedirs(audits_dir)
            print(f"Created {audits_dir} folder")

        # Step 2: Move all files from validated to audits
        validated_dir = "validated"
        if os.path.exists(validated_dir):
            moved_count = 0
            for filename in os.listdir(validated_dir):
                src_path = os.path.join(validated_dir, filename)
                if os.path.isfile(src_path):
                    dst_path = os.path.join(audits_dir, filename)
                    shutil.move(src_path, dst_path)
                    moved_count += 1
                    print(f"Moved: {filename} -> {audits_dir}")
            print(f"Moved {moved_count} files from {validated_dir} to {audits_dir}")
        else:
            print(f"No {validated_dir} folder found")

        # Step 3: Empty the JSON files
        json_files = ["collections.json", "validated.json", "reversed_collections.json"]
        for json_file in json_files:
            with open(json_file, "w") as f:
                json.dump([], f, indent=2)
            print(f"Emptied {json_file}")

        print("\n=== Cleanup completed successfully ===")

    except Exception as e:
        print(f"Error during cleanup: {e}")


if __name__ == '__main__':
    clean_up()