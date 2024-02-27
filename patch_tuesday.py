import requests
from datetime import datetime, timedelta
import logging
import re
from urllib.parse import quote
logging.getLogger("urllib3").setLevel(logging.WARNING)


logging.basicConfig(level=logging.DEBUG)

class MicrosoftVulnerabilityFetcher:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "accept": "application/json, text/plain, */*",
            "accept-language": "en-US,en;q=0.9",
            "access-control-allow-origin": "*",
            "cache-control": "no-cache",
            "origin": "https://msrc.microsoft.com",
            "pragma": "no-cache",
            "referer": "https://msrc.microsoft.com/",
            "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "x-request-id": "cc7c7dee-e588-45cf-a09f-aa8fd4f9e3d4"
        })

    def fetch_vulnerabilities(self):
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)
        filter_url = f"https://api.msrc.microsoft.com/sug/v2.0/fr-fr/affectedProduct?$orderBy=releaseDate%20desc&$filter=productFamilyId%20in%20(%27100000010%27)%20and%20productId%20in%20(%2712243%27)%20and%20impactId%20in%20(%27100000002%27)%20and%20(releaseDate%20ge%20{start_date.strftime('%Y-%m-%dT%H:%M:%S.000Z')})%20and%20(releaseDate%20le%20{end_date.strftime('%Y-%m-%dT%H:%M:%S.999Z')})"
        
        response = self.session.get(filter_url)
        """if response.status_code == 200:
            logging.debug(response.json())
        else:
            logging.error("Failed to fetch data")"""
        
        response.raise_for_status()  # Ensure the request was successful
        return response.json()["value"]
    
    def clean_html(html_content):
        """Remove HTML tags and decode HTML entities."""
        # Remove HTML tags
        text = re.sub('<[^<]+?>', '', html_content)
        return text
    

    @staticmethod
    def parse_response(data):
        # Parse and return all relevant information
        parsed_data = []
        for item in data['value']:
            parsed_data.append({
                "id": item['id'],
                "release_date": item['releaseDate'],
                "product": item['product'],
                "cve_number": item['cveNumber'],
                "severity": item['severity'],
                "impact": item['impact']
            })
        return parsed_data
    

    @staticmethod
    def fetch_cve_details(cve_number):
        """Fetch CVE details from the Microsoft API."""
        url = f"https://api.msrc.microsoft.com/sug/v2.0/fr-FR/vulnerability/{cve_number}"
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9',
            'origin': 'https://msrc.microsoft.com',
            'referer': 'https://msrc.microsoft.com/',
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return None

    @staticmethod
    def print_cve_details(data):
        """Print the specified details of the CVE in a structured format."""
        # Define fields to display with friendly names
        fields = {
            'cveTitle': "CVE Title",
            'tag': "Tag",
            'latestSoftwareRelease': "Latest Software Release",
            'exploited': "Exploited",
            'publiclyDisclosed': "Publicly Disclosed"
        }
        
        # Print each field with its friendly name and value
        for field, friendly_name in fields.items():
            print(f"{friendly_name}: {data.get(field, 'N/A')}")
        
        # Print articles if any
        print("\nArticles:")
        if 'articles' in data and data['articles']:
            for article in data['articles']:
                article_type = article.get('articleType', 'N/A')
                description = MicrosoftVulnerabilityFetcher.clean_html(article.get('description', 'N/A'))  # Use clean_html to remove HTML tags
                print(f"- {article_type}: {description}")
        else:
            print("No articles available.")

        print("\n" + "-"*80 + "\n")  # End of CVE details section

    @staticmethod
    def parse_and_pretty_print(data):
        for json_data in data:

            cve_number = json_data['cveNumber']

            print("-"*32)
            print(f"CVE Article: https://msrc.microsoft.com/update-guide/vulnerability/{cve_number}")
            if json_data['kbArticles']:  # Check if kbArticles is not empty
                first_article = json_data['kbArticles'][0]  # Assuming we're interested in the first article
                print(f"Download URL: {first_article['downloadUrl']}")
            else:
                print("Download URL: N/A")
            print(f"Release Number: {json_data['releaseNumber']}")
            print(f"Fixed Build Number: {first_article['fixedBuildNumber']}")

            data = MicrosoftVulnerabilityFetcher.fetch_cve_details(cve_number)

            if data:
                MicrosoftVulnerabilityFetcher.print_cve_details(data)
            else:
                print("Failed to fetch CVE details.")
            



# Usage
fetcher = MicrosoftVulnerabilityFetcher()
vulnerabilities = fetcher.fetch_vulnerabilities()
fetcher.parse_and_pretty_print(vulnerabilities)



