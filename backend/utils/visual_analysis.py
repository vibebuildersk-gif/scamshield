from PIL import Image
import imagehash
import os

def calculate_visual_similarity(live_screenshot_path, target_brand_folder="brand_templates"):
    """
    Compares the live website screenshot against our local signature database of high-target brands.
    Returns: (bool, str, float) -> (is_impersonating, brand_name, similarity_percentage)
    """
    if not os.path.exists(live_screenshot_path):
        return False, "None", 0.0
        
    try:
        # Load the live screenshot and calculate its 64-bit Perceptual Hash
        live_img = Image.open(live_screenshot_path)
        live_hash = imagehash.phash(live_img)
        
        # Dictionary mapping your saved template images to corporate identities
        brand_signatures = {
            "google_login.png": "Google Authentication",
            "microsoft_outlook.png": "Microsoft Outlook",
            "netflix_portal.png": "Netflix Inc."
        }
        
        # Hard threshold: If hashes differ by less than 10 bits, they are visually nearly identical layout structures
        BIT_THRESHOLD = 10 
        
        # Ensure brand_templates directory exists relative to this script
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        target_brand_folder = os.path.join(base_dir, target_brand_folder)
        os.makedirs(target_brand_folder, exist_ok=True)
        
        for template_file, brand_name in brand_signatures.items():
            template_path = os.path.join(target_brand_folder, template_file)
            if not os.path.exists(template_path):
                continue
                
            template_hash = imagehash.phash(Image.open(template_path))
            
            # Subtracting two image hashes calculates the Hamming Distance (number of bit differences)
            hamming_distance = live_hash - template_hash
            
            # Convert distance to an intuitive percentage score (64 total bits)
            similarity_pct = ((64 - hamming_distance) / 64) * 100
            
            if hamming_distance <= BIT_THRESHOLD:
                # High-risk brand match discovered!
                return True, brand_name, similarity_pct
                
        return False, "Unique Layout", 100.0
        
    except Exception as e:
        print(f"[-] Visual analysis error: {e}")
        return False, "Error", 0.0
