import boto3
import tqdm
import termcolor
from botocore.exceptions import ClientError

# Set up the CloudFormation client , use this in case you have an account connected via aws configure cli
cfn_client = boto3.client('cloudformation')

# Get the list of all regions
regions = [region['RegionName'] for region in boto3.client('ec2').describe_regions()['Regions']]

#set CloudFormation stackname prefix
prefix = "-lightlytics-"

#set CloudFormation prefix of nested stack to ingore it
n1prefix = "-LightlyticsCollectionLambdas-"

#set CloudFormation prefix of nested stack to ingore it
n2prefix = "-LightlyticsInitLambdas-"

# Iterate over each region
for region in regions:
    # Set up a new CloudFormation client for the current region
    cfn_client = boto3.client('cloudformation', region_name=region)

    # Get the list of stacks in the region
    stacks = cfn_client.list_stacks()['StackSummaries']

    # Filter the list of stacks to only include a specific prefix and status is complete create or update complete

    stacks = [stack for stack in stacks if (prefix in stack['StackName'] and (stack['StackStatus'] == 'CREATE_COMPLETE' or stack['StackStatus'] == 'UPDATE_COMPLETE')) and not n1prefix in stack['StackName']and not n2prefix in stack['StackName']]
    
    #pring all found stacks names
    print([stack['StackName'] for stack in stacks])

    # Iterate over each stack and update it
    for stack in tqdm.tqdm(stacks, desc=f"Updating stacks in {region}"): 
        stack_name = stack['StackName']
        try:            
            # Update the stack using the existing template
             cfn_client.update_stack(StackName=stack_name, UsePreviousTemplate=True)    

             # Wait for the update to complete
             cfn_client.get_waiter('stack_update_complete').wait(StackName=stack_name)

            # Print the name of the stack that was successfully updated
             print(termcolor.colored(f"Successfully updated stack {stack_name} in {region}", "green"))

        except ClientError as e:

            # Print an error message if the stack no longer exists
             print(termcolor.colored(f"Failed to update stack {stack_name} in {region}: {e}", "red"))
