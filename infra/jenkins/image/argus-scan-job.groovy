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
    new StringParameterDefinition('GIT_URL', '', 'SOURCE_TYPE=git일 때 clone할 HTTPS 주소입니다.', true),
    new StringParameterDefinition('GIT_REF', '', '브랜치 또는 태그 이름입니다. 비워 두면 기본 브랜치를 사용합니다.', true),
    new CredentialsParameterDefinition('GIT_CREDENTIALS_ID',
        '비공개 저장소에 접근할 Username with password 자격 증명입니다. 비밀번호 칸에 토큰을 넣습니다.',
        '', 'com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl', false),
    new StringParameterDefinition('LOCAL_PATH', '', 'SOURCE_TYPE=local일 때 sources 디렉터리 기준의 상대 경로입니다.', true),
    new ChoiceParameterDefinition('BUILD_JDK', ['auto', '8', '17', '21'] as String[],
        'Gradle 의존성을 해석할 때 사용할 JDK입니다. auto는 Gradle wrapper 버전으로 결정합니다.'),
]))
job.save()
