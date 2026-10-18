package org.sempersupra.aar.jadx;

import javax.swing.*;
import java.awt.*;
import java.util.concurrent.CompletionException;

/** No automatic remote egress. A separate disclosure confirmation guards each call. */
public final class ActorAssistPanel extends JDialog {
    private final String source;
    private final JComboBox<AssistProfile.Provider> provider =
        new JComboBox<>(AssistProfile.Provider.values());
    private final JComboBox<AssistProfile.Role> role =
        new JComboBox<>(AssistProfile.Role.values());
    private final JComboBox<String> mode = new JComboBox<>(new String[]{
        "explain","obfuscation","kotlin-r8","security","counterexample"});
    private final JTextField model = new JTextField(30);
    private final JTextArea question = new JTextArea(3,55);
    private final JTextArea output = new JTextArea(20,75);
    private final JButton ask = new JButton("Generate hypotheses (not verified)");
    private final AssistGateway gateway = new AssistGateway();

    public ActorAssistPanel(String code) {
        super((Frame)null,"AAR JADX Actor Assist — experimental",false);
        source=code == null ? "" : code;
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout(8,8));
        JPanel controls=new JPanel(new GridLayout(0,2,5,5));
        controls.add(new JLabel("Provider / egress"));controls.add(provider);
        controls.add(new JLabel("Interview role"));controls.add(role);
        controls.add(new JLabel("Exact model ID"));controls.add(model);
        controls.add(new JLabel("Task"));controls.add(mode);
        controls.add(new JLabel("Selected code size"));
        controls.add(new JLabel(source.length()+" chars; >12000 refused"));
        controls.add(new JLabel("Privacy"));
        controls.add(new JLabel("Remote OpenRouter requires explicit confirmation each call"));
        provider.addActionListener(e -> resetModel());
        resetModel();
        add(controls,BorderLayout.NORTH);
        output.setEditable(false);
        output.setLineWrap(true);
        output.setWrapStyleWord(true);
        output.setFont(new Font(Font.MONOSPACED,Font.PLAIN,12));
        add(new JScrollPane(output),BorderLayout.CENTER);
        JPanel bottom=new JPanel(new BorderLayout());
        bottom.add(new JScrollPane(question),BorderLayout.CENTER);
        ask.addActionListener(e -> request());
        bottom.add(ask,BorderLayout.SOUTH);
        add(bottom,BorderLayout.SOUTH);
        pack();
        setLocationRelativeTo(null);
    }
    private void resetModel() {
        AssistProfile.Provider p=(AssistProfile.Provider)provider.getSelectedItem();
        model.setText(p==AssistProfile.Provider.OPENROUTER_FREE ?
            System.getenv().getOrDefault("AAR_ASSIST_OPENROUTER_FREE_MODEL","") :
            p==AssistProfile.Provider.OPENROUTER_MANAGED ?
            System.getenv().getOrDefault("AAR_ASSIST_OPENROUTER_MANAGED_MODEL","") :
            System.getenv().getOrDefault("AAR_ASSIST_LOCAL_MODEL","qwen3.6:35b-a3b"));
    }
    private void request() {
        final AssistProfile profile;
        final EvidencePrompt.Packet packet;
        try {
            profile=AssistProfile.fromSelection((AssistProfile.Provider)provider.getSelectedItem(),
                (AssistProfile.Role)role.getSelectedItem(),model.getText().trim());
            packet=EvidencePrompt.build(source,(String)mode.getSelectedItem(),question.getText());
        } catch (RuntimeException ex) {
            output.setText("BLOCKED: "+ex.getMessage()+"\nNo inference executed.");
            return;
        }
        boolean external=profile.provider == AssistProfile.Provider.OPENROUTER_FREE
            || profile.provider == AssistProfile.Provider.OPENROUTER_MANAGED;
        if (external) {
            int choice=JOptionPane.showConfirmDialog(this,
                "The selected decompiled source ("+source.length()+
                " characters) will be transmitted to OpenRouter and an upstream model provider.\n"+
                (profile.provider == AssistProfile.Provider.OPENROUTER_MANAGED ?
                    "METERED INFERENCE: OpenRouter credits or a BYOK provider account may be charged.\n" : "")+
                "Do not send private APKs, credentials, sensitive content or unauthorized code.\n"+
                "Continue with exact model "+profile.model+"?",
                "EXTERNAL SOURCE DISCLOSURE — approve this request?",JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);
            if (choice!=JOptionPane.YES_OPTION) {
                output.setText("NOT_SENT: external inference denied.");
                return;
            }
        }
        ask.setEnabled(false);
        output.setText("IN_PROGRESS: "+profile.provider+"/"+profile.model+
            "\ncode SHA256 "+packet.sha256+
            "\nRole "+profile.role+". Answers are hypotheses until independently verified.");
        gateway.generate(profile,packet,external).whenComplete((reply,err) ->
            SwingUtilities.invokeLater(() -> {
                ask.setEnabled(true);
                if (err!=null) {
                    Throwable c=err instanceof CompletionException ? err.getCause():err;
                    String code=c instanceof SecurityException ? "PRIVACY_OR_KEY_GATE" :
                        c instanceof IllegalStateException ? c.getMessage() : "INCOMPLETE_TRANSPORT";
                    output.setText("NOT_QUALIFIED: "+code+"\nNo behavioral or recovery evidence.");
                } else {
                    output.setText("UNVERIFIED MODEL HYPOTHESES\nRequested model "+reply.model+
                        "\nProvider-reported model "+reply.observedModel+
                        "\nActual BYOK account route: UNKNOWN"
                        "\nCode SHA256 "+reply.codeSha256+
                        "\nPrompt "+reply.promptVersion+
                        "\nMust independently confirm every claim using DEX/JVM/behavior oracles.\n\n"+
                        reply.text);
                }
            }));
    }
}
