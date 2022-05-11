#!/usr/bin/env groovy

library("govuk")

REPOSITORY = 'govuk-csp-forwarder'

repoName = JOB_NAME.split('/')[0]

node {
  env.REPO      = 'alphagov/govuk-csp-forwarder'
  env.BUILD_DIR = '__build'
  env.GOPATH    = "${WORKSPACE}/${BUILD_DIR}"
  env.SRC_PATH  = "${env.GOPATH}/src/github.com/${REPO}"

  try {
    stage("Checkout") {
      checkout scm
    }

    stage("Setup build environment") {
      // Clean GOPATH: Recursively delete everything in the current directory
      dir(env.GOPATH) {
        deleteDir()

        // Create Build-Path
        sh "mkdir -p ${env.SRC_PATH}"
      }

      // Seed Build-Path
      dir(env.WORKSPACE) {
        sh "/usr/bin/rsync -a ./ ${env.SRC_PATH} --exclude=$BUILD_DIR"
      }
    }

    // Start Build
    stage("Build") {
      dir(env.SRC_PATH) {
        sh 'go build -o $WORKSPACE/csp_forwarder csp_forwarder.go'
        sh 'zip -j $WORKSPACE/csp_forwarder.zip $WORKSPACE/csp_forwarder'
      }
    }

    // Archive Binaries from build
    stage("Archive Artifact") {
      archiveArtifacts 'csp_forwarder'
    }

    // Push the Go binary for the build to S3, for AWS releases
    if (env.BRANCH_NAME == "main") {
      stage("Push binary to S3") {
        govuk.uploadArtefactToS3('csp_forwarder.zip', "s3://govuk-integration-artefact/govuk-csp-forwarder/release/csp_forwarder.zip")
        target_tag = "release_${env.BUILD_NUMBER}"
        govuk.uploadArtefactToS3('csp_forwarder.zip', "s3://govuk-integration-artefact/govuk-csp-forwarder/${target_tag}/csp_forwarder.zip")
      }
    }

    if (env.BRANCH_NAME == "main") {
      stage("Push release tag") {
        govuk.pushTag('govuk-csp-forwarder', env.BRANCH_NAME, 'release_' + env.BUILD_NUMBER)
      }
    }
  } catch (e) {
      currentBuild.result = "FAILED"
      step([$class: 'Mailer',
            notifyEveryUnstableBuild: true,
            recipients: 'govuk-ci-notifications@digital.cabinet-office.gov.uk',
            sendToIndividuals: true])
    throw e
  }
}
