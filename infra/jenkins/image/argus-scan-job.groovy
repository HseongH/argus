// Creates or refreshes the argus-scan pipeline job on every Jenkins start.
// Parameters are declared here (not in the Jenkinsfile) so the job is runnable before its first build.
import com.cloudbees.plugins.credentials.CredentialsParameterDefinition
import hudson.model.ChoiceParameterDefinition
import hudson.model.ParametersDefinitionProperty
import hudson.model.StringParameterDefinition
import jenkins.model.Jenkins
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition
import org.jenkinsci.plugins.workflow.job.WorkflowJob

def jobName = 'argus-scan'
def jenkinsfile = new File('/opt/argus/Jenkinsfile')
def jenkins = Jenkins.get()

def job = jenkins.getItemByFullName(jobName, WorkflowJob) ?: jenkins.createProject(WorkflowJob, jobName)
job.description = '애플리케이션 소스를 스캔해 SARIF와 CycloneDX SBOM을 /reports 아래에 저장합니다.'
job.definition = new CpsFlowDefinition(jenkinsfile.text, true)
job.removeProperty(ParametersDefinitionProperty)
job.addProperty(new ParametersDefinitionProperty([
    new StringParameterDefinition('APP_NAME', '',
        '보고서 폴더 이름입니다. 영문, 숫자, 점(.), 밑줄(_), 하이픈(-)만 사용할 수 있습니다.', true),
    new ChoiceParameterDefinition('SOURCE_TYPE', ['git', 'local'] as String[],
        'git: 원격 저장소를 clone합니다. local: 호스트의 sources 디렉터리 아래에 있는 소스를 사용합니다.'),
    new StringParameterDefinition('GIT_URL', '',
        'SOURCE_TYPE=git일 때 clone할 주소입니다. HTTPS(https://...)와 SSH(git@... 또는 ssh://...)를 지원합니다.', true),
    new StringParameterDefinition('GIT_REF', '', '브랜치 또는 태그 이름입니다. 비워 두면 기본 브랜치를 사용합니다.', true),
    new CredentialsParameterDefinition('GIT_CREDENTIALS_ID',
        '비공개 저장소용 자격 증명입니다. HTTPS 주소는 Username with password(비밀번호 칸에 토큰), ' +
        'SSH 주소는 SSH Username with private key 자격 증명을 선택합니다.',
        '', 'com.cloudbees.plugins.credentials.common.StandardCredentials', false),
    new StringParameterDefinition('LOCAL_PATH', '', 'SOURCE_TYPE=local일 때 sources 디렉터리 기준의 상대 경로입니다.', true),
    new StringParameterDefinition('SOURCE_LABEL', '',
        'manifest.json에 기록할 원본 소스 위치입니다. 비워 두면 GIT_URL 또는 LOCAL_PATH를 기록합니다.', true),
    new ChoiceParameterDefinition('BUILD_JDK', ['auto', '8', '17', '21'] as String[],
        'Gradle 의존성을 해석할 때 사용할 JDK입니다. auto는 Gradle wrapper 버전으로 결정합니다.'),
]))
job.save()
