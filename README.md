# Boat Cargo Assignment Cloud App
This project lets you interact with an API backend that manages cargo assignments to boats. Certain interactions are protected via OAuth2 authentication. **Using this project will require that you have a GCP account, set up a OAuth consent screen for the account, and have Google Cloud SDK Shell installed and setup on your machine.**

## Description
The backend is implemented using Flask which interacts with the GCP Datastore (NoSQL) service. The user can perform the following actions:
1. Create/Delete/Retrieve/Edit boats
2. Create/Delete/Retrieve/Edit cargo
3. Assign/Unassign cargo to boats

Calls to the Flask backend are done via HTTP API calls to their appropriate endpoints. Certain actions are "protected" and will require that you login to Google to obtain a JWT token containing the appropriate authorization field in order for the Flask backend to authenticate the action.

Available API endpoints and their requirements are documented in the PDF named "Boat Cargo Assignment Cloud App API Spec".

## How to Use
1. Download the repo somewhere you can reach
2. Open Google Cloud SDK Shell and navigate to the repo directory
3. Deploy the directory's contents using the Shell (GCP AppEngine)
4. Copy the app's URL via the shell
5. Using a browser, navigate to the app's URL to be redirected to a Google login page
6. Sign-in with your credentials and you will be redirected to a page displaying your JWT token information (you just need the "access_token")
7. Using whatever HTTP calling app you want (e.g. Postman), made a Header called "Authorization" and give it the value of "Bearer ...whatever_your_access_token_value_is..."
8. You can now start making calls to any of the app's endpoints
