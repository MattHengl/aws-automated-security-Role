/*!
     * Copyright 2017-2017 Mutual of Enumclaw. All Rights Reserved.
     * License: Public
*/ 

//Mutual of Enumclaw 
//
//Matthew Hengl and Jocelyn Borovich - 2019 :) :)
//
//Main file that controls remediation and notifications of all IAM Role events. 
//Remediates actions when possible or necessary based on launch type and tagging. Then, notifies the user/security. 

//Make sure to that the master.invalid call does NOT have a ! infront of it
//Make sure to delete or comment out the change in the process.env.environtment

const AWS = require('aws-sdk');
AWS.config.update({region: process.env.region});
const iam = new AWS.IAM();
const epsagon = require('epsagon');
const dynamodb = new AWS.DynamoDB();
const Master = require("aws-automated-master-class/MasterClass").handler;
let path = require("aws-automated-master-class/MasterClass").path; 
let master = new Master();

let improperLaunch = false;

//Variables that allow these functions to be overridden in Jest testing by making the variable = jest.fn() 
//instead of its corresponding function
let callAutoTag = autoTag;
let callCheckTagsAndAddToTable = checkTagsAndAddToTable;
let callRemediate = remediate;
let callRemediateDynamo = remediateDynamo;

//Only used for testing purposes
setIamFunction = (value, funct) => {
   iam[value] = funct;
};

//**********************************************************************************************
//remediates a specific action after receiving an event log
async function handleEvent(event) {

   console.log(JSON.stringify(event));
   path.p = 'Path: \nEntering handleEvent';

   //Conditionals for a dynamo eventy
   if(master.checkDynamoDB(event)){
      
      let convertedEvent = master.dbConverter(event);

      //Extra console.log statements for testing ===================================
      if (convertedEvent.ResourceName) {
         console.log(`"${convertedEvent.ResourceName}" is being inspected----------`);
      } else {
         console.log(`"${event.Records[0].dynamodb.Keys.ResourceName.S}" is being inspected----------`);
      }
      //==================================================

      //remediation process and checking tags for a Dynamodb event
      if (convertedEvent.ResourceType == "Role" && event.Records[0].eventName == 'REMOVE'){
         path.p += '\n/Event is of type Role and has an event of REMOVE';
         try{
            let tags = await iam.listRoleTags({RoleName: convertedEvent.ResourceName}).promise();
            if (!(master.tagVerification(tags.Tags))) {
               path.p += '\n/Resource has the incorrect tags';
               await callRemediateDynamo(event, convertedEvent)
               await master.notifyUser(event, convertedEvent , 'Role');
            }    
         }
         catch(e){
            console.log(e);
            path.p += '\n/ERROR';
            console.log(path.p);
            return e;
         }     
      } else {
         path.p += '\n/Event was not of type Role and didn\'t have an event of REMOVE';
      } 
      console.log(path.p);
      return;
   }

   try{

      var trueEventName = event.detail.eventName;
      console.log(trueEventName);

      event = master.devTest(event);
      //Checks the event log for any previous errors. Stops the function if there is an error. 
      if (master.errorInLog(event)) {
         console.log(path.p);
         return; 
      }
      
      console.log(`"${event.detail.requestParameters.roleName}" is being inspected----------`);
      console.log(`Event action is ${event.detail.eventName}---------- `);
   
      //Conditionals to stop the function from continuing
      if (master.selfInvoked(event)) {
         console.log(path.p);
         return;
      }
         
      //Checks if the event is invalid. If it is invalid, then remediate. Else check for tags and add to the table with a TTL
      //if(master.checkKeyUser(event, 'roleName')){
         //Delete the ! if there is one. Only use ! for testing.
         if(master.invalid(event)){
           improperLaunch = true;
           console.log('Calling notify user and remediate');
           let results = await callRemediate(event);
           await master.notifyUser(event, results, 'Role');
           //create a variable that you can compare instead of the data from the event itself
           if(event.detail.eventName == 'CreateRole' || event.detail.eventName.includes('Delete')){
               console.log('Event is either CreateRole or DeleteRole');
               console.log(path.p);
               return;
           }
         }
         if(event.detail.eventName.includes('Delete')){
            let results = await callRemediate(event);
            await master.notifyUser(event, results, 'Role');
         }else{
            await callCheckTagsAndAddToTable(event);
         }
         console.log(path.p);
         // delete path.p;
      //}
   }catch(e){
      console.log(e);
      path.p += '\n/ERROR';
      console.log(path.p);
      return e;
   }
}


//**********************************************************************************************
//Checks for and auto adds tags and then adds resource to the table if it is missing any other tags
async function checkTagsAndAddToTable(event) {
   path.p += '\n/Entering checkTagsAndAddToTable, Created params for function call';
   let params = { RoleName: event.detail.requestParameters.roleName };
   let tags = {};

   try {
      path.p += '\n/Calling AutoTag function';
      tags = await callAutoTag(event, params);
      console.log(tags);
      if (!(master.tagVerification(tags.Tags))) {
         await master.putItemInTable(event, 'Role', params.RoleName);
         return true;
      } else {
         return false;
      }
   } catch(e) {
      console.log(e); 
      path.p += '\n/ERROR';
      return e;
   }
}


//**********************************************************************************************
//Remediates the action performed and sends an email
async function remediate(event) {

   console.log('Entered the remediation function');
   path.p += '\n/Entered the remediation function';
   
   //Sets up required parameters for remediation
   const erp = event.detail.requestParameters;
   
   let params = {
      RoleName: erp.roleName
   };

   results = await master.getResults(event, { ResourceName: params.RoleName });
   console.log(results);

   //Decides, based on the incoming event name, which function to call to perform remediation
   try {
      switch(results.Action){
         case "CreateRole": 
            path.p += '\n/CreateRole';
            results.Response = 'DeleteRole';
            results.Reason = 'Improper Launch';
            await callRemediateDynamo(event, results);
         break;
         case "PutRolePolicy":
            path.p += '\n/PutRolePolicy';            
            params.PolicyName = erp.policyName;
            await overrideFunction('deleteRolePolicy', params);
            results.ResourceName = erp.policyName;
            results.Response = "DeleteRolePolicy";
         break;
         case "AttachRolePolicy":
            path.p += '\n/AttachRolePolicy'; 
            params.PolicyArn = erp.policyArn;
            await overrideFunction('detachRolePolicy', params);
            results.ResourceName = erp.policyArn;
            results.Response = "DetachRolePolicy";
         break;
         case "DetachRolePolicy":
            path.p += '\n/DetachRolePolicy'; 
            params.PolicyArn = erp.policyArn;
            await overrideFunction('attachRolePolicy', params);
            results.ResourceName = erp.policyArn;
            results.Response = "AttachRolePolicy";
         break;
         case "DeleteRolePolicy":
            path.p += '\n/DeleteRolePolicy'; 
            results.ResourceName = erp.policyName;
            results.Response = "Remediation could not be performed";
         break; 
         case "DeleteRole": 
            path.p += '\n/DeleteRole';
            results.Response = 'Remediation could not be performed';
            // if(master.snd()){ 
               //Something is going wrong here and needs to be fixed. 
               //Error is being thrown. Possibly because the role is already being deleted from the table.
               if(await master.checkTable(results.ResourceName, 'Role')){
                  path.p += '\n/Item still in table';
                  let tableParams = {
                     TableName: `remediation-db-table-${process.env.environment}-ShadowRealm`,
                     Key: {
                        'ResourceName': { 
                           S: results.ResourceName
                        }, 
                        'ResourceType': {
                           S: 'Role'
                        }
                     }
                  }
                  console.log('Created the tableParams');
                  await dynamodb.deleteItem(tableParams).promise();
                  path.p += '\n/Deleted the item from the table';
               }
            //}
         break;
      }
   } catch(e) {
      console.log(e); 
      path.p += '\n/ERROR';
      console.log("**************NoSuchEntity error caught**************");
      return e;
   }
   
   results.Reason = 'Improper Tags';
   if (improperLaunch) {
      results.Reason = 'Improper Launch';
   }
   if (results.Response == 'Remediation could not be performed') {
      delete results.Reason;
   }
   path.p += '\n/Remediation was finished';
   console.log(results);
   return results;
}


//**********************************************************************************************
//Function to remediate the event coming from DynamoDB. Remediates all attachments before removing the role
async function remediateDynamo(event, results){

   console.log('Entered RemediateDynamo');
   path.p += '\n/Entered RemediateDynamo';
   let params = {}; 
   if (results.KillTime) {
      params = { RoleName: results.ResourceName };
   } else {
      params = { RoleName: event.detail.requestParameters.roleName };
   }

   //lists the attachments
   let inline = {}; 
   let attached = {};
   console.log('Getting the API calls back to see if the role has attached or inline policies');
   try {
      inline = await iam.listRolePolicies(params).promise(); 
      attached = await iam.listAttachedRolePolicies(params).promise();
   } catch(e) {
      console.log(e); 
      path.p += '\n/ERROR';
      console.log("**************NoSuchEntity error caught**************");
      return e;
   }

   console.log('Checking');
   //checks if there is at least one attachment that needs remediation
   if (inline.PolicyNames[0] || attached.AttachedPolicies[0]) { 

      console.log('Resource has attached or inline policies');
      
      let newEvent = event;  
      if (results.KillTime) {
         path.p += '\n/Event is a DynamoDB event and There are inline and attached policies';
         let requestParameters = {
            roleName: params.RoleName,
            policyName: '',
            policyArn: '' 
         };
         newEvent = master.translateDynamoToCloudwatchEvent(event, requestParameters);
      }
      
      //Remediates all the inline policies
      if (inline.PolicyNames[0]) {
         console.log('inline');
         path.p += '\n/Remediating inline policies';
         for (let i = 0; i < inline.PolicyNames.length; i++) {
            newEvent.detail.requestParameters.policyName = inline.PolicyNames[i];
            newEvent.detail.eventName = 'PutRolePolicy';
            await callRemediate(newEvent);
            
         }
      }
      //Remediates all the attached policies
      if (attached.AttachedPolicies[0]) {
         console.log('attached');
         path.p += '\n/Remediating attached policies';
         for (let i = 0; i < attached.AttachedPolicies.length; i++) {
            newEvent.detail.requestParameters.policyArn = attached.AttachedPolicies[i].PolicyArn;
            newEvent.detail.eventName = 'AttachRolePolicy';;
            await callRemediate(newEvent);
         }   
      }
   }

   console.log('Finished remediation of policies');
   path.p += '\n/Finished remediation of policies';
   let InstanceProfiles = await iam.listInstanceProfilesForRole(params).promise();
   console.log('After the listing instance profiles for roles');

   //removes an instance profile, if it is attached, from the role in order to delete the role.
   if (InstanceProfiles.InstanceProfiles[0]) {

      console.log('There is an instance profile');
      params.InstanceProfileName = params.RoleName;
      path.p += '\n/Deleting the instance profile to delete role';
      await overrideFunction('removeRoleFromInstanceProfile', params);
      console.log('After the instance profile was deleted');
      delete params.InstanceProfileName;
   } 

   //Deletes the role
   console.log('Deleting the role');
   await overrideFunction('deleteRole', params);
   console.log('After deleting the role');
   path.p += '\n/Role was deleted';
   console.log(results);
   return results;
}


//**********************************************************************************************
//Automatically adds missing tags, tag3 and Environment, if needed 
async function autoTag(event, params) {

   let tags = await iam.listRoleTags(params).promise();

   //checks if env is sandbox AND checks for and adds tag3 tag
   if (master.snd() && master.needsTag(tags.Tags, `${process.env.tag3}`)){
      
      //Adds the tag3 tag to the resource
      await iam.tagRole(await master.getParamsForAddingTags(event, params, `${process.env.tag3}`)).promise();
      tags = await iam.listRoleTags(params).promise();
      path.p += `\n/Adding ${process.env.tag3} to resource`;
   }
   
   //checks if the resource has an environment tag and adds it if it doesn't
   if (master.needsTag(tags.Tags, 'Environment')) {
      
      //Adds the Environment tag to the resource
      await iam.tagRole(await master.getParamsForAddingTags(event, params, 'Environment')).promise();
      tags = await iam.listRoleTags(params).promise();
      path.p += '\n/Adding Environment to resource';
   }
   return tags;
}

async function overrideFunction(apiFunction, params){
   if(process.env.run == 'false'){
      //epsagon.label('remediate', 'true');
      path.p += `\n/Overriding ${apiFunction}`;
      await setIamFunction(apiFunction, (params) => {
         console.log(`Overriding ${apiFunction}`);
         return {promise: () => {}};
      });
      path.p += `\n/Done overriding ${apiFunction}`;
   }
   await iam[apiFunction](params).promise();
 };


exports.handler = handleEvent;
exports.checkTagsAndAddToTable = checkTagsAndAddToTable; 
exports.remediateDynamo = remediateDynamo;
exports.autoTag = autoTag;
exports.remediate = remediate;

//overrides the given function (only for jest testing)
exports.setIamFunction = (value, funct) => {
   iam[value] = funct;
};

exports.setDBFunction = (value, funct) => {
   dynamodb[value] = funct;
};

exports.setAutoTag = (funct) => {
   callAutoTag = funct;
};

exports.setRemediate = (funct) => {
   callRemediate = funct;
};

exports.setRemediateDynamo = (funct) => {
   callRemediateDynamo = funct;
};

exports.setCheckTagsAndAddToTable = (funct) => {
   callCheckTagsAndAddToTable = funct;
};





//Created by Matthew Hengl and Jocelyn Borovich. Ur fav 2019 interns!! :) :)
