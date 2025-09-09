import pandas as pd
import os

print("📂 Merging feedback into main dataset...")

main_path = "Data/malicious_phish.csv"
feedback_path = "feedback.csv"

# Load main dataset
df = pd.read_csv(main_path)

# Load feedback if exists
if os.path.exists(feedback_path):
    fb_df = pd.read_csv(feedback_path)

    if not fb_df.empty:
        print(f"✅ Found {len(fb_df)} feedback samples")

        # Repeat feedback rows (weighting)
        weight_factor = 10  # <-- adjust this to make feedback stronger
        fb_df = pd.concat([fb_df] * weight_factor, ignore_index=True)

        # Merge
        df = pd.concat([df, fb_df], ignore_index=True)

        # Save back to main dataset
        df.to_csv(main_path, index=False)
        print(f"✅ Merged {len(fb_df)} weighted feedback samples into {main_path}")

        # Clear feedback.csv
        open(feedback_path, "w").write("url,type\n")
        print("🧹 feedback.csv cleared")
    else:
        print("ℹ️ No new feedback to merge")
else:
    print("⚠️ feedback.csv not found")

print("🎉 Merge process completed.")