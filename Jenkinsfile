def buildComands = [
    "notification-service": "mvn clean package", 
    "custom-metric-publisher": "npm install && cd src && npm install",
    "lambda-authorizer": "mvn clean package",
    "likeness-and-liveness": "mvn clean package",
    "poc-chain-of-custody": "mvn clean package",
    "fingerprint-device-service": "mvn clean package"
]

def servicePlugins = [
    "notification-service": [
        "serverless-better-credentials",
        "serverless-s3-sync",
        "serverless-domain-manager"
    ],
    "custom-metric-publisher": [
        "serverless-better-credentials",
        "serverless-apigateway-service-proxy",
        "serverless-iam-roles-per-function",
        "serverless-associate-waf"
    ] ,
    "lambda-authorizer": [
        "serverless-better-credentials"
    ],
    "likeness-and-liveness": [
        "serverless-better-credentials",
        "serverless-iam-roles-per-function",
        "serverless-domain-manager",
        "serverless-associate-waf"
    ],
    "poc-chain-of-custody": [
        "serverless-better-credentials",
        "serverless-iam-roles-per-function",
        "serverless-domain-manager"
    ],
    "fingerprint-device-service": [
        "serverless-better-credentials",
        "serverless-s3-sync",
        "serverless-domain-manager",
        "serverless-associate-waf"
    ]
]

def jdk_map = [
    "lambda-authorizer" : "JDK17GRAALVM",
    "likeness-and-liveness" : "JDK17GRAALVM",
    "notification-service": "JDK17",
    "fingerprint-device-service": "JDK17"
]


currentProdClusterAlias = "satin" // current_prod_cluster_alias variable that define which cluster is prod now
currentStagingClusterAlias = "beige"

properties([
    parameters([
        [
            $class: 'ChoiceParameter', choiceType: 'PT_SINGLE_SELECT', name: 'SERVICE', 
                description: 'Service to update',
                script: [
                    $class: 'GroovyScript', 
                    fallbackScript: [classpath: [], sandbox: false, script: 'return ["error"]'], 
                    script: [
                        classpath: [], 
                        sandbox: false, 
                        script:  'return ["notification-service", "custom-metric-publisher", "lambda-authorizer", "likeness-and-liveness", "poc-chain-of-custody","fingerprint-device-service"]'
                    ]
                ]
        ],
        [
            $class: 'CascadeChoiceParameter', choiceType: 'PT_SINGLE_SELECT', name: 'BRANCH', referencedParameters: 'SERVICE', 
                description: 'Branch to build from',
                script: [
                    $class: 'GroovyScript', 
                    fallbackScript: [classpath: [], sandbox: false, script: 'return ["main"]'], 
                    script: [
                        classpath: [], 
                        sandbox: false, 
                        script: 
                            '''
                                import jenkins.model.*
                                 credentialsId = 'github_token'
                                def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
                                  org.jenkinsci.plugins.plaincredentials.StringCredentials.class, Jenkins.instance, null, null ).find{
                                  it.id == credentialsId}
                                process = [ 'bash', '-c', "curl -s -H \\\"Accept: application/vnd.github+json\\\" -H \\\"Authorization: Bearer ${creds.secret}\\\" https://api.github.com/repos/transport-exchange-group/trustd-${SERVICE}/branches | grep name | cut -d\\\\\\" -f4" ].execute()
                                process.waitFor()
                                def output = process.text
                                return output.replaceAll('\\n',',').split(',').toList()
                            '''
                    ]
                ]
        ]
    ])
])

def ENVIRONMENT_VAR = 'pink'
    

def clusterMap = [
    pink : 'orange-aqua',
    aqua: 'orange-aqua',
    cyan: 'orange-aqua',
    beige: 'beige',
    satin: 'satin'
]

def CLUSTER_IDENTIFIER_VAR = clusterMap[ENVIRONMENT_VAR]

if (!CLUSTER_IDENTIFIER_VAR) {
    error "Invalid ENVIRONMENT: ${ENVIRONMENT_VAR}"
}


def CLUSTER_IDENTIFIER = CLUSTER_IDENTIFIER_VAR

pipeline{
    agent any
    // agent{
    //     kubernetes {
    //         inheritFrom 'trustd-serverless'
    //         yaml """
    //           spec:
    //             serviceAccountName: ${"trustd-" + "${CLUSTER_IDENTIFIER_VAR}" }
    //         """
    //     }
    // }
    parameters{
        booleanParam(name: 'DELETE_IF_FAILED', defaultValue: true, description: 'DELETE sls stack in case FAILED')
        booleanParam(name: 'DELETE', defaultValue: false, description: 'Only DELETE checked service')
       // string(name: 'ADDITIONAL_PARAMETERS', defaultValue: 'env=orange', description: 'Instructions for automation. Left blank if run by manual. For now supported format: env=env_name')
        choice(name: 'ENVIRONMENT', choices: ['pink', 'aqua','cyan','beige','satin'], description: 'Environment to deploy app to')
        //string(name: 'CLUSTER_IDENTIFIER', defaultValue: 'orange-aqua', description: 'Cluster identifier. Unique name of the cluster')
        booleanParam(name: 'SKIP_ACM', defaultValue: true, description: 'If you sure that ACM was created earlier')
    }
    tools{
        nodejs 'nodejs-14.x'
        maven 'maven-3.x'
        jdk "${ jdk_map[params.SERVICE] ?: 'JDK11' }"
    }
    stages{
        stage('Checkout'){
            steps{
                script{
                    // if ( params.ENVIRONMENT == 'automated-env' ) { // in this case <env_name> will be read from ADDITIONAL_PARAMETERS (env=<env_name>) instead of ENVIRONMENT
                    //     separator = '='
                    //     ENVIRONMENT_VAR=params.ADDITIONAL_PARAMETERS.replaceAll('.*env.*'+separator,'').trim()
                    //     echo "DEBUG: ENVIRONMENT_VAR: ${ENVIRONMENT_VAR}"
                    // } else {
                    //     error("It is only 'automated-env' choice compatible for now. Please use this choice")
                        ENVIRONMENT_VAR = params.ENVIRONMENT // for compatibility
                    // }
                    accountID = sh(script: 'aws sts get-caller-identity --query "Account" --output text', returnStdout: true).trim()
                    
                    region = "eu-west-1" // set default region
                    if (accountID != "513296374752") { // this is the main TrustD-account
                        if (params.SERVICE != 'likeness-and-liveness') { // likeness-and-liveness use Rekognition that doesn't works in the 'us-east-2' region
                            region = "us-east-2"
                        }
                    }
                        
                    echo "${region}" //debug
                    checkout([$class: 'GitSCM',
                              branches: [[name: "${params.BRANCH}"]],
                              userRemoteConfigs: [[credentialsId:  'github_access',
                                   url: "ssh://git@github.com/transport-exchange-group/trustd-${params.SERVICE}.git"]]])

                    additional_parameters_for_domain = "--param=\"certificateName=*.${ENVIRONMENT_VAR}.trustd.net\"" //yaroslav.gankov - separated var for domain certificate override
                    additional_parameters = ''
                    if ( params.SERVICE == "notification-service") {
                        echo "DEBUG: accountID: ${accountID}" // debug
                        kms_key_id = sh(script: "aws kms describe-key --key-id arn:aws:kms:${region}:${accountID}:alias/fingerprint-device-service --query \"KeyMetadata.KeyId\" --output text", returnStdout: true).trim()
                        echo "DEBUG: kms_key_id: ${kms_key_id}" // debug
                        temp_workloadVpcId=sh(script: "aws ssm get-parameter --name 'workload_vpc_id' --region ${region} --query 'Parameter.Value' --output text", returnStdout: true).trim()
                        echo "DEBUG: temp_workloadVpcId: ${temp_workloadVpcId}" // debug
                        additional_parameters = "--param=\"KMSKeyId=${kms_key_id}\" ${additional_parameters_for_domain}"
                    }
                    if ( params.SERVICE == "custom-metric-publisher") {
                        kms_key_id = sh(script: "aws kms describe-key --key-id arn:aws:kms:${region}:${accountID}:alias/custom-metric-publisher --query \"KeyMetadata.KeyId\" --output text", returnStdout: true).trim()
                        echo "DEBUG: kms_key_id: ${kms_key_id}" // debug
                        additional_parameters = "--param=\"KMSKeyId=${kms_key_id}\" ${additional_parameters_for_domain}"
                    }

                    if ( params.SERVICE == "poc-chain-of-custody" || params.SERVICE == "fingerprint-device-service" || params.SERVICE == "notification-service" ) {
                        privateSubnetsIds = sh(script: "aws ssm get-parameter --name 'privateSubnetsIds' --region ${region} --with-decryption --query \"Parameter.Value\" --output text", returnStdout: true).trim()
                        if ( params.SERVICE == "fingerprint-device-service" ) {
                            sg_parameter_name="eksClusterSecurityGroupId"
                        } else {
                            sg_parameter_name="defaultSecurityGroupId"
                        }
                        customSecurityGroupId = sh(script: "aws ssm get-parameter --name '${sg_parameter_name}' --region ${region} --with-decryption --query \"Parameter.Value\" --output text", returnStdout: true).trim()
                        additional_parameters = additional_parameters + " --param=\"subnetIds=${privateSubnetsIds}\" --param=\"securityIds=${customSecurityGroupId}\" "
                    }

                    if ( params.SERVICE == "notification-service" || params.SERVICE == "fingerprint-device-service" ) {
                        s3_bucket_name_to_cp = "${params.SERVICE}-trustd-${ENVIRONMENT_VAR}"
                        additional_parameters = additional_parameters + " && aws s3 cp flyway/migration s3://${s3_bucket_name_to_cp}/${ENVIRONMENT_VAR} --sse aws:kms --recursive"
                        echo "DEBUG: additional_parameters: ${additional_parameters}" // debug
                        additional_parameters_delete = "&& aws s3 rm s3://${s3_bucket_name_to_cp} --recursive"
                    }                    
                    // Generate properties file from template if not exists
                    path_to_properties="src/main/resources"
                    properties_file="${path_to_properties}/application-${ENVIRONMENT_VAR}.properties"
                    if ( ifFileExists(properties_file) == false ) {
                        if ( params.SERVICE != "custom-metric-publisher" ) {
                            echo "DEBUG: properties file '${properties_file}' not found. Create that one"
                            sh "cp ${path_to_properties}/application.properties.template ${properties_file}"
                            sh """
                                sed -i "s|env_name_var|${ENVIRONMENT_VAR}|g" ${properties_file}
                            """
                            if ( params.SERVICE == "fingerprint-device-service" || params.SERVICE == "likeness-and-liveness" ) {
                                url_sqs_custom_metric_publisher = sh(script: "aws sqs list-queues --queue-name-prefix custom-metric-publisher --query \"QueueUrls[?contains(@, '${ENVIRONMENT_VAR}')]\" --output yaml | grep -v 'DeadLetterQueue' | sed 's/.* //g'", returnStdout: true).trim()
                                sh """
                                    set +x
                                    sed -i "s|paste_url_sqs_custom_metric_publisher_here|${url_sqs_custom_metric_publisher}|g" ${properties_file}
                                    sed -i "s|s3_bucket=trustd-likeness-and-liveness|s3_bucket=trustd-likeness-and-liveness-eu-west-1-${ENVIRONMENT_VAR}|g" ${properties_file}
                                    set -x
                                """
                            }

                            // supporting staging and prod (if beige switched as staging - we need to use app.staging.trustd.net instead of app.beige.trustd.net)
                            echo "DEBUG: ${ENVIRONMENT_VAR} == ${currentStagingClusterAlias}" // delete this debug after testing
                            if ( ENVIRONMENT_VAR == currentStagingClusterAlias ) {
                                sh """
                                    sed -i "s|https://app.${ENVIRONMENT_VAR}.trustd.net/auth|https://app.staging.trustd.net/auth|g" ${properties_file}
                                """
                            }
                            if ( ENVIRONMENT_VAR == currentProdClusterAlias ) {
                                sh """
                                    sed -i "s|https://app.${ENVIRONMENT_VAR}.trustd.net/auth|https://app.trustd.net/auth|g" ${properties_file}
                                """
                            }


                            sh "cat ${properties_file}" //debug
                        }
                    }
                    // }
                    if (params.SERVICE ==~ 'notification-service|likeness-and-liveness|fingerprint-device-service') {
                        // needed to have credentials in the ~/.aws/credentials and ~/.aws/config to domain plugin
                        sh '''#!/bin/bash
                            set +x
                            path="$HOME/.aws/cli/cache"
                            filename=$(ls $path)
                            export AWS_ACCESS_KEY_ID=$(jq -r ".Credentials.AccessKeyId" $path/$filename) 
                            export AWS_SECRET_ACCESS_KEY=$(jq -r ".Credentials.SecretAccessKey" $path/$filename)
                            export AWS_SESSION_TOKEN=$(jq -r ".Credentials.SessionToken" $path/$filename) 
                            mkdir -p ~/.aws 
                            echo "[default]" > ~/.aws/credentials
                            echo "aws_access_key_id = ${AWS_ACCESS_KEY_ID}" >> ~/.aws/credentials 
                            echo "aws_secret_access_key = ${AWS_SECRET_ACCESS_KEY}" >> ~/.aws/credentials 
                            echo "aws_session_token = ${AWS_SESSION_TOKEN}" >> ~/.aws/credentials 
                            echo "[profile default]" > ~/.aws/config
                            echo "region = us-east-2" >> ~/.aws/config
                            echo "output = json" >> ~/.aws/config
                            set -x
                        '''
                    }
                    currentBuild.displayName = "#${env.BUILD_NUMBER} - ${params.SERVICE} - ${ENVIRONMENT_VAR}"
                    currentBuild.description = params.BRANCH
                }
            }
        }
        stage('Delete') {
            when {
                anyOf {
                    expression { params.DELETE }
                }
            }
            steps {
                script {
                    currentBuild.description = currentBuild.description + '\n' + 'delete'
                    echo "DEBUG: param DELETE is set to true - so lambdas will be deleted"
                    pluginList = servicePlugins[params.SERVICE].join(" ")
                    sh "export NODE_OPTIONS=\"--dns-result-order=ipv4first\"" //needed to get around error 'npm ERR! code ENETUNREACH'
                    sh "npm install --save-dev serverless aws-sdk @serverless/utils ${pluginList}"
                    if (params.SERVICE ==~ 'notification-service|likeness-and-liveness|fingerprint-device-service|custom-metric-publisher') {
                        try {
                            sh "sls delete_domain --stage ${ENVIRONMENT_VAR} --region ${region} --verbose ${additional_parameters_delete}"
                        } catch (Exception e) {
                            echo "ERROR: delete_domain (above ↑↑↑↑↑↑) exited with the some ERROR but we continue..."
                        }
                    }
                    try {
                        sh "sls remove --stage ${ENVIRONMENT_VAR} --region ${region}"
                    } catch (Exception e) {
                        echo "ERROR: sls remove (above ↑↑↑↑↑↑) exited with the some ERROR but we continue..."
                    }
                }
            }
        }
        stage('Build'){
            when {
                expression { ! params.DELETE }
            }
            steps{
                script {
                    if ( ! params.SKIP_ACM ) {
                        build job: "trustd/acm_route53/create-ACM-and-route53", parameters: [
                            string(name: 'ENVIRONMENT', value: "${ENVIRONMENT_VAR}"),
                            string(name: 'CLUSTER_IDENTIFIER', value: "${CLUSTER_IDENTIFIER_VAR}"),
                            string(name: 'REGION', value: region),
                        ]
                    } else {
                        echo "DEBUG: job trustd/acm_route53/create-ACM-and-route53 was skipped due to parameter of the Job"
                    }
                    cmd = buildComands[params.SERVICE]
                    sh "${cmd}"
                }
            }
        }
        stage('Deploy'){
            when {
                expression { ! params.DELETE }
            }
            steps{
                script{
                    pluginList = servicePlugins[params.SERVICE].join(" ")
                    sh "export NODE_OPTIONS=\"--dns-result-order=ipv4first\"" //needed to get around error 'npm ERR! code ENETUNREACH'
                    if ( params.SERVICE == "custom-metric-publisher" ) {
                        serverless_version="serverless@3.21"
                    }
                    else {
                        serverless_version="serverless"
                    }

                    sh "npm install --save-dev ${serverless_version} aws-sdk @serverless/utils ${pluginList}"
                    if (params.SERVICE ==~ 'notification-service|likeness-and-liveness|fingerprint-device-service') {
                        sh "sls create_domain --stage ${ENVIRONMENT_VAR} --region ${region} ${additional_parameters_for_domain}"
                    }
                }
                script {
                    // preparation custom description
                    CommitID = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
                    message = "Branch: " + params.BRANCH + ". CommitID: " + CommitID
                    print(message)
                    sh "sed -i 's/  Description: Custom description/  Description: \"${message}\"/' serverless.yml"

                    command_deploy = "SLS_DEBUG=* sls deploy --stage ${ENVIRONMENT_VAR} --region ${region} --verbose ${additional_parameters}"
                    sh "${command_deploy}"
                }
            }
        }
    }
    post {
        failure {
            script {
                if ( params.DELETE_IF_FAILED ) {
                    echo "DEBUG(post): param DELETE_IF_FAILED is set to true - so all FAILED lambdas will be deleted"
                    if (params.SERVICE ==~ 'notification-service|likeness-and-liveness|fingerprint-device-service') {
                        try {
                            sh "sls delete_domain --stage ${ENVIRONMENT_VAR} --region ${region} --verbose ${additional_parameters_delete}"
                        } catch (Exception e) {
                            echo "ERROR(post): delete_domain (above ↑↑↑↑↑↑) exited with the some ERROR but we continue..."
                        }
                    }
                    try {
                        sh "sls remove --stage ${ENVIRONMENT_VAR} --region ${region}"
                    } catch (Exception e) {
                        echo "ERROR(post): sls remove (above ↑↑↑↑↑↑) exited with the some ERROR but we continue..."
                        currentBuild.result = 'FAILURE'
                    }
                }
            }
        }
        always {
            script {
                if ( params.DELETE ) {
                    command = "sls deploy list --stage ${ENVIRONMENT_VAR} --region ${region}"
                    echo "DEBUG(post): delete case. Trying to run command: ${command}"
                    output = sh(script: "${command} || true", returnStdout: true).trim().replaceAll('\\n',' ')
                    echo "DEBUG(post): output: ${output}"
                    if ( output ==~ /Error:.*Stack.*does not exist(.*)/ ) {
                        echo "DEBUG(post): will mark as SUCCESS because we wanted to delete serverless but it doesn't exist"
                        currentBuild.description = currentBuild.description + ' - stack didn\'t exist'
                        currentBuild.result = 'SUCCESS'
                    } else {
                        currentBuild.result = 'FAILED'
                    }
                }
            }
        }
    }
}

def ifFileExists(String path_to_file) {
    def file_exists = sh(script: "test -f ${path_to_file} > /dev/null 2>&1", returnStatus: true)
    if ( file_exists != 0 ) {
        return false
    } else {
        return true
    }
}
