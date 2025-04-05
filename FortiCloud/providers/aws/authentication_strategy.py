import boto3
import logging

from ScoutSuite import __version__
from ScoutSuite.providers.aws.utils import get_caller_identity
from ScoutSuite.providers.base.authentication_strategy import AuthenticationStrategy, AuthenticationException


class AWSCredentials:

    def __init__(self, session):
        self.session = session


class AWSAuthenticationStrategy(AuthenticationStrategy):
    """
    Implements authentication for the AWS provider
    """

    def authenticate(self,
                     profile=None,
                     aws_access_key_id=None, aws_secret_access_key=None, aws_session_token=None,
                     **kwargs):

        try:

            # Set logging level to error for libraries as otherwise generates a lot of warnings
            logging.getLogger('botocore').setLevel(logging.ERROR)
            logging.getLogger('botocore.auth').setLevel(logging.ERROR)
            logging.getLogger('urllib3').setLevel(logging.ERROR)
            
            #if profile is provided, use it to create a session. else, AWS Access keys are provided, use it to create a session. 
            if profile:
                session = boto3.Session(profile_name=profile)
            elif aws_access_key_id and aws_secret_access_key:
                if aws_session_token:                     #use AWS session token for temporary credentials 
                    session = boto3.Session(
                        aws_access_key_id=aws_access_key_id,
                        aws_secret_access_key=aws_secret_access_key,
                        aws_session_token=aws_session_token,
                    )
                else:                                  # else use permanent acess key and secret key
                    session = boto3.Session(
                        aws_access_key_id=aws_access_key_id,
                        aws_secret_access_key=aws_secret_access_key,
                    )
            else:                                   #if no credentials, use default credentials (like- Environment Variables)
                session = boto3.Session()     

            # Test querying for current user (validating)
            get_caller_identity(session)

            # Set custom user agent
            session._session.user_agent_name = 'Scout Suite'
            session._session.user_agent_extra = 'Scout Suite/{} (https://github.com/nccgroup/ScoutSuite)'.format(__version__)
            session._session.user_agent_version = __version__

            return AWSCredentials(session=session)

        except Exception as e:
            raise AuthenticationException(e)
