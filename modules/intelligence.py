import os
import logging
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class IntelligentAnalyzer:
    def __init__(self, config):
        self.config = config
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.model = self.config.get("ai_model", "gpt-3.5-turbo")
        
        if not self.api_key:
            logging.warning("OPENAI_API_KEY not found. AI analysis will be skipped.")
            self.client = None
        else:
            self.client = OpenAI(api_key=self.api_key)

    def analyze(self, scan_results):
        """
        Analyzes scan results using the OpenAI API.
        """
        if not self.client:
            return "AI Analysis Skipped: OPENAI_API_KEY not found in environment variables."

        try:
            logging.info(f"Sending scan results to OpenAI ({self.model})...")
            
            # Construct a prompt based on scan results
            prompt = self._construct_prompt(scan_results)
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert Cybersecurity Consultant."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=500
            )
            
            analysis = response.choices[0].message.content
            return analysis

        except Exception as e:
            error_msg = f"AI Analysis Failed: {str(e)}"
            logging.error(error_msg)
            return error_msg

    def _construct_prompt(self, scan_results):
        """
        Creates a prompt for the LLM based on scan data.
        """
        # Simplify the scan data to reduce token usage
        summary = "Scan Results:\n"
        
        if not scan_results or 'scan' not in scan_results:
             return "No open ports found. The target appears secure."

        for host, data in scan_results['scan'].items():
            summary += f"Host: {host}\n"
            for proto in data.get('tcp', {}):
                service = data['tcp'][proto]
                summary += f"- Port {proto}: {service.get('name', 'unknown')} (Version: {service.get('version', '')})\n"
        
        prompt = (
            f"{summary}\n\n"
            "Analyze these findings. Identify potential risks, highlight critical vulnerabilities, "
            "and suggest top 3 remediation steps. detailed but concise."
        )
        return prompt
