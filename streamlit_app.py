import streamlit as st
import requests
import json
import boto3
from botocore.exceptions import ClientError
import fitz


def verify_ip_address():
    """
        Validate the users IP address
    :return:
    """
    is_valid_ip: bool = False
    ip_address = ''

    response = requests.get("https://api.ipify.org?format=json")

    if response.status_code == 200:
        ip_address = json.loads(response.content)['ip']

        if ip_address in st.secrets.ips.whitelisted:
            is_valid_ip: bool = True

    return is_valid_ip, ip_address


def authenticate_user(user_key: str) -> bool:
    """
        Validate the User Key to prevent unauthorised access
    :param user_key: User Key
    :return: user_validated (True/False)
    """
    is_user_validated: bool = True

    if user_key == st.secrets.user_key.hash:
        is_user_validated: bool = True

    return is_user_validated

def extract_text_from_pdf(pdf_file):
    doc = fitz.open(stream=pdf_file.read(), filetype="pdf")
    text = ""
    for page_num in range(len(doc)):
        page = doc.load_page(page_num)
        text += page.get_text()
    return text

# Show title and description.
st.title("📄 DoXplain")
st.write(
    "Upload a document below and ask a question about it – GPT will answer! "
    "To use this app, you need to provide a User Authentication Key. "
)



is_valid_ip, ip_address = verify_ip_address()

if not is_valid_ip:
    st.info(f"{ip_address} is not a Whitelisted IP", icon="💀")

else:
    user_key = st.text_input("Key", type="password")
    if not user_key:
        st.info("Please add the User Key for Authentication.", icon="🗝️")
    else:
        if len(user_key) == st.secrets.user_key.max_length:
            is_user_validated = authenticate_user(user_key)

            if is_user_validated:

                model_type_option = st.selectbox(label='Select the Model Type', options=st.secrets.model.type_names,
                                                 placeholder="Choose an option", index=None,)
                st.write('You selected: ', model_type_option)

                if model_type_option:
                    model_option = st.selectbox(label='Select the Model ID', options=st.secrets.model.ids[model_type_option],
                                                placeholder="Choose an option", index=None,)
                    st.write('You selected: ', model_option)

                    uploaded_file = st.file_uploader(
                        "Upload a document (.txt or .md pr .pdf)", type=("txt", "md", 'pdf')
                    )

                    # Ask the user for a question via `st.text_area`.
                    question = st.text_area(
                        "Now ask a question about the document!",
                        placeholder="Can you give me a short summary?",
                        disabled=not uploaded_file,
                    )

                    if uploaded_file and question:
                        pdf_text = extract_text_from_pdf(uploaded_file)
                        # pdf_text = uploaded_file.read().decode()
                        if question:
                            response_obj = requests.get(st.secrets.aws_url.link)
                            response_obj.raise_for_status()
                            aws_credential_dict = response_obj.json()

                            client = boto3.client(
                                "bedrock-runtime",
                                aws_access_key_id=aws_credential_dict["AccessKeyId"],
                                aws_secret_access_key=aws_credential_dict["SecretAccessKey"],
                                aws_session_token=aws_credential_dict["SessionToken"],
                                region_name="us-east-1"
                            )
                            st.info("Connected to model")
                            model_id = model_option

                            user_message = (f"Here's a document: {pdf_text} \n\n---\n\n {question}")

                            conversation = [
                                {
                                    "role": "user",
                                    "content": [{"text": user_message}],
                                }
                            ]

                            try:
                                # Send the message to the model
                                response = client.converse(
                                    modelId=model_id,
                                    messages=conversation,
                                    inferenceConfig={"maxTokens": 512, "temperature": 0.5, "topP": 0.9},
                                )
                                # Extract and print the response text
                                response_text = response["output"]["message"]["content"][0]["text"]
                                print(response_text)
                            except (ClientError, Exception) as e:
                                print(f"ERROR: Can't invoke '{model_id}'. Reason: {e}")
                                exit(1)

                            st.write(response_text)
