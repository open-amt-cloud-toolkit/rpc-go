pipeline{
    agent {
        label 'docker-amt'
    }
    options {
        buildDiscarder(logRotator(numToKeepStr: '5', daysToKeepStr: '30'))
        timestamps()
        timeout(unit: 'HOURS', time: 2)
    }
    stages{
        stage('Cloning Repository') {
            steps{ 
                script{
                    scmCheckout {
                        clean = true
                    }
                }
            }
        }
        stage('Static Code Scan') {
            steps{
                script{
                    staticCodeScan {
                        // generic
                        scanners             = ['checkmarx', 'protex', 'snyk']
                        scannerType          = 'go'

                        protexProjectName    = 'OpenAMT - RPC-GO'
                        // internal, do not change
                        protexBuildName      = 'rrs-generic-protex-build'

                        checkmarxProjectName = "OpenAMT - RPC"

                        //snyk details
                        snykManifestFile        = ['go.mod']
                        snykProjectName         = ['openamt-rpc']
                    }
                }
            }
        }
    }
}
