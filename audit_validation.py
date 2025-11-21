import json
import os
import time
from datetime import datetime

import pyperclip
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager

from questions import validation_format

BASE_URL = "https://deepwiki.com/sei-protocol/sei-cosmos"


class Validator:
    def __init__(self, teardown=False):

        s = Service(ChromeDriverManager().install())
        self.options = webdriver.ChromeOptions()

        # --- Add these two lines here ---
        self.options.add_argument("--headless")
        self.options.add_argument("--window-size=1920,1080")
        # ---------------------------------

        # removed headless so the browser window is visible
        # ensure window is visible and starts maximized
        self.options.add_argument('--start-maximized')
        self.teardown = teardown
        # keep chrome open after chromedriver exits
        self.options.add_experimental_option("detach", True)
        self.options.add_experimental_option(
            "excludeSwitches",
            ['enable-logging'])
        self.driver = webdriver.Chrome(
            options=self.options,
            service=s)
        self.driver.implicitly_wait(50)
        self.validated_url = []
        super(Validator, self).__init__()

    def __enter__(self):
        self.driver.get(BASE_URL)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.teardown:
            self.driver.quit()

    def toggle_deep_research(self):
        wait = WebDriverWait(self.driver, 20)

        xpath = '//button[.//span[normalize-space(text())="Fast"]]'
        btn = wait.until(EC.element_to_be_clickable((By.XPATH, xpath)))
        btn.click()

        xpath_primary = "//div[@role='menuitem' and .//span[normalize-space(text())='Deep Research']]"
        menu_item = wait.until(EC.element_to_be_clickable((By.XPATH, xpath_primary)))
        menu_item.click()

    def ask_question(self,filename, question_gotten):
        wait = WebDriverWait(self.driver, 1200)

        try:
            self.driver.get(BASE_URL)

            # # wait for the form containing the textarea
            form = wait.until(
                EC.presence_of_element_located((By.CSS_SELECTOR, 'form'))
            )

            # find the textarea inside the form
            textarea = form.find_element(By.CSS_SELECTOR, 'textarea')
            self.toggle_deep_research()

            # type the question
            textarea.click()
            textarea.clear()
            formatted_question = validation_format(question_gotten)

            # Use JavaScript to set the textarea value directly. It's more reliable for large text.
            self.driver.execute_script("arguments[0].value = arguments[1];", textarea, formatted_question)
            # Dispatch an 'input' event to make sure the web application detects the change.
            self.driver.execute_script("arguments[0].dispatchEvent(new Event('input', { bubbles: true }));",
                                       textarea)
            textarea.send_keys(".. ")

            textarea.send_keys(Keys.ENTER)

            time.sleep(10)
            current_url = self.driver.current_url

            # add the current url to validated
            self.save_to_validated(filename,current_url)
        except Exception as a:
            print(f"There was an error in index : {a}")

            # In your Deepwiki class where you save to validated.json

    def save_to_validated(self,filename, url):
        """Save question and URL to collections.json"""
        validated_file = "validated.json"

        # Load existing data or start fresh
        try:
            if os.path.exists(validated_file):
                with open(validated_file, "r") as f:
                    content = f.read().strip()
                    data = json.loads(content) if content else []
            else:
                data = []
        except json.JSONDecodeError:
            print("Invalid validated.json, creating new file")
            data = []

        # Add new entry
        data.append({
            "filename": filename,
            "url": url,
            "timestamp": str(datetime.now()),
            "report_generated": False
        })

        # Save with proper formatting
        try:
            with open(validated_file, "w") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving to validated: {e}")


class GetValidatedReports:
    def __init__(self, teardown=False):

        s = Service(ChromeDriverManager().install())
        self.options = webdriver.ChromeOptions()

        # --- Add these two lines here ---
        # self.options.add_argument("--headless")
        # self.options.add_argument("--window-size=1920,1080")
        # ---------------------------------

        # removed headless so the browser window is visible
        # ensure window is visible and starts maximized
        self.options.add_argument('--start-maximized')
        self.teardown = teardown
        # keep chrome open after chromedriver exits
        self.options.add_experimental_option("detach", True)
        self.options.add_experimental_option(
            "excludeSwitches",
            ['enable-logging'])
        self.driver = webdriver.Chrome(
            options=self.options,
            service=s)
        self.driver.implicitly_wait(50)
        self.validated_url = []
        super(GetValidatedReports, self).__init__()

    def get_report(self, url):

        try:
            self.driver.get(url)

            wait = WebDriverWait(self.driver, 120)
            #  this would click the copy button
            copy_button_selector = (By.CSS_SELECTOR, '[aria-label="Copy"]')
            all_copy_buttons = wait.until(
                EC.presence_of_all_elements_located(copy_button_selector)
            )
            last_copy_button = all_copy_buttons[-1]
            wait.until(EC.element_to_be_clickable(last_copy_button)).click()

            xpath = "//div[@role='menuitem' and normalize-space(text())='Copy response']"
            el = wait.until(EC.element_to_be_clickable((By.XPATH, xpath)))
            el.click()

            clipboard_content = pyperclip.paste()

            # Check if the content exists AND if it does NOT contain the "#NoVulnerability" string
            if clipboard_content and "#NoVulnerability" not in clipboard_content and "#No" not in clipboard_content:
                filename = f"validated/audit_{self.get_next_report_number()}.md"
                with open(filename, "w") as f:
                    f.write(clipboard_content)
                print(f"Saved report for question {url} to {filename}")
            else:
                # This will now handle both empty clipboard and cases where no vulnerability was found
                print(f"No vulnerability found or clipboard was empty for: '{url}'")

            # Clear textarea for next question
            self.mark_report_generated(url)
            time.sleep(1)  # give it a moment to clear
        except Exception as e:
            print(f"There was an error in index {url}: {e}")

    def mark_report_generated(self, url):
        """Mark this URL's report as generated in validated.json"""
        if not url:
            return

        try:
            with open("validated.json", "r") as f:
                data = json.load(f)

            # Find and update the item
            for item in data:
                if item.get("url") == url:
                    item["report_generated"] = True
                    break

            with open("validated.json", "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error marking report as generated: {e}")

    def get_next_report_number(self):
        """Get the next available report number"""
        if not os.path.exists("validated"):
            os.makedirs("validated")
            return 1

        existing_files = [f for f in os.listdir("validated") if f.startswith("audit_") and f.endswith(".md")]

        if not existing_files:
            return 1

        # Extract numbers from existing files
        numbers = []
        for f in existing_files:
            try:
                num = int(f.replace("audit_", "").replace(".md", ""))
                numbers.append(num)
            except ValueError:
                continue

        return max(numbers) + 1 if numbers else 1
