pipeline {
  agent {
    docker {
      image 'python:3.11-slim'
      args '-u' // stdout sin buffer
    }
  }
  options { timestamps() }
  parameters {
    choice(name: 'CONFIG', choices: ['configs/dev.json','configs/prod.json'], description: 'Config JSON')
  }
  environment { PYTHONUNBUFFERED = '1' }

  stages {
    stage('Checkout') {
      steps { deleteDir(); checkout scm }
    }
    stage('Deps') {
      steps {
        sh '''
          pip install --no-cache-dir --upgrade pip
          pip install --no-cache-dir requests psycopg2-binary python-dotenv
        '''
      }
    }
    stage('Run audit') {
      steps {
        withCredentials([
          usernamePassword(credentialsId: 'GRAFANA_CREDS', usernameVariable: 'GRAFANA_USERNAME', passwordVariable: 'GRAFANA_PASSWORD'),
          usernamePassword(credentialsId: 'PG_CREDS',      usernameVariable: 'DB_USER',          passwordVariable: 'DB_PASSWORD')
        ]) {
          sh 'python audit_navpanel_first_prod.py -c ${CONFIG} | tee run.log'
        }
      }
    }
  }
  post {
    always { archiveArtifacts artifacts: 'run.log', allowEmptyArchive: true }
  }
}
