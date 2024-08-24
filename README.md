# Local LLM UI with Authentication and Weekly Email Report

### Overview:

Develop a secure local UI with authentication features and automated email reporting for enhanced user interaction and data management.

### _Features_:

1. _UI Development_:
   - Design and implement a user-friendly interface using Flask/Django, ensuring intuitive navigation and accessibility.
2. _Authentication Feature_:
   - Integrate OAuth or similar authentication mechanisms to secure user access and protect sensitive data.
3. _Chat Log Feature_:
   - Implement local storage for chat logs, ensuring data encryption and compliance with privacy regulations.
4. _Weekly Email Report_:
   - Develop a scheduled task to compile and send weekly chat logs to designated email addresses, enhancing user engagement and transparency.

### _Steps_:

1. Download Ollama
2. Run any LLM of your preference (Ex: ollama run qwen2:0.5b)
3. Clone the Local LLM repo, install the requirements using: pip install -r requirements.txt
4. Fill in the Google, Github, Mail username and Mail password (For the account that needs to recieve the weekly chatlog update).
5. The chat encription key is needed to encrypt the chatlog data. It is optional, and a default key is generated in case not provided by user.
6. Run: python http://app.py

### _Tips and Potential Improvements_:

- _Security Enhancements_: Implement SSL/TLS encryption for secure data transmission and storage, safeguarding user information.
- _User Feedback_: Incorporate feedback mechanisms to iterate UI/UX design based on user preferences and usability testing.
- _Integration Capabilities_: Explore API integrations for seamless data exchange with external systems, enhancing functionality and scalability.
