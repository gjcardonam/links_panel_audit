pipeline {
  agent any
  triggers { cron('H 3 * * *') } // corre diario alrededor de las 03:00
  options { timestamps() }
  parameters {
    choice(name: 'CONFIG', choices: ['configs/dev.json', 'configs/prod.json'], description: 'Config JSON a usar')
    booleanParam(name: 'VERIFY_SSL', defaultValue: true, description: 'Verificar SSL contra Grafana')
  }
  environment {
    DB_HOST   = 'rds-test.cj8e8cqeonv7.us-east-2.rds.amazonaws.com'
    DB_PORT   = '5432'
    DB_NAME   = 'postgres'
    DB_SCHEMA = 'public'
    ENV_NAME  = 'jenkins'
    PYTHONUNBUFFERED = '1'
  }
  stages {
    stage('Checkout') {
      steps { checkout scm }
    }
    stage('Python venv & deps') {
      steps {
        sh '''
          python3 -m venv venv
          . venv/bin/activate
          pip install --upgrade pip
          pip install requests psycopg2-binary python-dotenv
        '''
      }
    }
    stage('Run audit') {
      steps {
        withCredentials([
          usernamePassword(credentialsId: 'grafana-creds', usernameVariable: 'GRAFANA_USERNAME', passwordVariable: 'GRAFANA_PASSWORD'),
          usernamePassword(credentialsId: 'pg-creds',      usernameVariable: 'DB_USER',          passwordVariable: 'DB_PASSWORD')
        ]) {
          sh '''
            . venv/bin/activate
            export GRAFANA_URL=$(jq -r '.grafana.url' ${CONFIG})   || true
            export VERIFY_SSL=${VERIFY_SSL}
            # DB params están en JSON excepto user/pass (que vienen de Credentials)
            python audit_navpanel_first_prod.py -c ${CONFIG} | tee run.log
          '''
        }
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'run.log', onlyIfSuccessful: false, allowEmptyArchive: true
    }
  }
}
