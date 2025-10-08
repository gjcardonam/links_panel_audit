pipeline {
  agent any
  options { timestamps() }
  parameters {
    choice(name: 'CONFIG', choices: ['configs/dev.json','configs/prod.json'], description: 'Config JSON')
  }
  environment { PYTHONUNBUFFERED = '1' }
  stages {
    stage('Checkout') {
      steps {
        deleteDir()
        checkout scm
      }
    }
    stage('Python & deps (user)') {
      steps {
        sh '''
          python3 --version
          python3 -m pip install --user --upgrade pip
          python3 -m pip install --user --no-cache-dir requests psycopg2-binary python-dotenv
          # Asegura que scripts instalados en ~/.local/bin están en el PATH de esta shell
          export PATH="$HOME/.local/bin:$PATH"
          # prueba import rápido
          python3 -c "import requests, psycopg2, dotenv; print('deps OK')"
        '''
      }
    }
    stage('Run audit') {
      steps {
        withCredentials([
          usernamePassword(credentialsId: 'GRAFANA_CREDS', usernameVariable: 'GRAFANA_USERNAME', passwordVariable: 'GRAFANA_PASSWORD'),
          usernamePassword(credentialsId: 'PG_CREDS',      usernameVariable: 'DB_USER',          passwordVariable: 'DB_PASSWORD')
        ]) {
          sh '''
            export PATH="$HOME/.local/bin:$PATH"
            python3 audit_navpanel_first_prod.py -c ${CONFIG} | tee run.log
          '''
        }
      }
    }
  }
  post {
    always { archiveArtifacts artifacts: 'run.log', allowEmptyArchive: true }
  }
}
