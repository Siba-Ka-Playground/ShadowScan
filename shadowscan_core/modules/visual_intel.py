import exifread
import os
import pillow_heif
pillow_heif.register_heif_opener()

class VisualIntel:
    """
    Pillar 2: Visual Intelligence Module
    Extracts invisible metadata (EXIF) from raw photos to find location and device info.
    """
    def __init__(self, image_path):
        self.image_path = image_path

    def extract_metadata(self):
        """
        Extracts GPS, Device Model, and Timestamp info from the image file headers.
        """
        findings = []
        
        # 1. Validation: Check if file exists
        if not os.path.exists(self.image_path):
            return [{"type": "Error", "data": f"Image file not found: {self.image_path}", "risk_level": "Info"}]

        try:
            with open(self.image_path, 'rb') as f:
                tags = exifread.process_file(f)
                
                # 2. GPS Coordinates (The "Holy Grail" of OSINT)
                if 'GPS GPSLatitude' in tags and 'GPS GPSLongitude' in tags:
                    lat = str(tags['GPS GPSLatitude'])
                    lon = str(tags['GPS GPSLongitude'])
                    
                    # Basic conversion logic could be added here to make it decimal, 
                    # but raw data is sufficient for proof of concept.
                    findings.append({
                        "type": "Geolocation",
                        "data": f"Coordinates found: Lat {lat}, Lon {lon}",
                        "risk_level": "CRITICAL"
                    })
                
                # 3. Device Information (e.g., iPhone 13 Pro)
                # Useful for tailoring phishing attacks (e.g., sending an iOS update link)
                if 'Image Model' in tags:
                    findings.append({
                        "type": "Device Intel",
                        "data": f"Camera Model: {str(tags['Image Model'])}",
                        "risk_level": "Medium"
                    })
                    
                # 4. Date & Time Original
                # Helps establish a "Pattern of Life" (when was the user active?)
                if 'Image DateTime' in tags:
                    findings.append({
                        "type": "Temporal Intel",
                        "data": f"Photo taken on: {str(tags['Image DateTime'])}",
                        "risk_level": "High"
                    })

                # 5. Software Used (e.g., Photoshop, Adobe Lightroom)
                # Indicates if the image was edited/doctored
                if 'Image Software' in tags:
                     findings.append({
                        "type": "Metadata Editing",
                        "data": f"Software used: {str(tags['Image Software'])}",
                        "risk_level": "Medium"
                    })
                    
        except Exception as e:
            findings.append({"type": "Error", "data": f"Metadata extraction failed: {str(e)}", "risk_level": "Low"})
            
        # If no specific tags were found but file opened successfully
        if not findings:
             findings.append({"type": "Info", "data": "No EXIF metadata found (Clean Image).", "risk_level": "Low"})

        return findings