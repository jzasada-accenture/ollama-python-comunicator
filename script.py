import requests
import json

def read_report(report_path: str) -> dict:
        with open(report_path, 'r') as file:
            return json.load(file)
        
def make_request(prompt):
    url = "http://localhost:11434/api/generate"
    headers = {
    "Content-Type": "application/json"
    }
    data = {
    "model": "llama3.2",
    "system": "You are an expert in analyzing SAST reports and detecting false positives. Each false positive should be marked and have a description of why it is false positive with at least 2 arguments.",
    "prompt": f"Analyze this case: {prompt}",
    "stream": False
    }
    return requests.post(url, headers=headers, data=json.dumps(data))



class Vuln:
     def __init__(self, input_dump: str):
          self.input_dump = input_dump
          self.additional_description: str

class Report:
    def __init__(self, input, input_type, output_type=None):
        self.input = input
        self.input_type = input_type
        self.output_type = output_type
        self.vulnerabilities = []

    def split_report(self) -> None:
        for i in self.input['report']['vulnerabilities']:
             j = json.dumps(i)
             j = j[1:-1]
             self.vulnerabilities.append(Vuln(j))

    def make_analysis(self) -> None:
        print("Starting analysis. This may take some time...")
        all = len(self.vulnerabilities)
        for i, vuln in enumerate(self.vulnerabilities):
            vuln.additional_description = make_request(vuln.input_dump).json()
            del vuln.additional_description["context"]
            print(f'{i+1}/{all} Done')

    def make_report(self) -> None:
         output_dict = {"vulnerabilities": [x.additional_description for x in self.vulnerabilities]}
         output_json = json.dumps(output_dict, indent=4)
         with open('output_report.json', 'w') as file:
              file.write(output_json)
        

if __name__ == '__main__':
    r0 = Report(read_report('test_report.json'), 'json', None)
    r0.split_report()
    r0.make_analysis()
    r0.make_report()

    