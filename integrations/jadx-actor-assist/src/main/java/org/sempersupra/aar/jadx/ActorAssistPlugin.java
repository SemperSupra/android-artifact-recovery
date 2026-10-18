package org.sempersupra.aar.jadx;

import jadx.api.JavaNode;
import jadx.api.plugins.JadxPlugin;
import jadx.api.plugins.JadxPluginContext;
import jadx.api.plugins.JadxPluginInfo;
import jadx.api.plugins.gui.JadxGuiContext;

import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

/** Human-in-the-loop GUI bridge; transport is separately unit-testable. */
public final class ActorAssistPlugin implements JadxPlugin {
    @Override
    public JadxPluginInfo getPluginInfo() {
        return new JadxPluginInfo("aar-actor-assist","AAR Actor Assist",
            "Source-bound reverse engineering hypotheses, local and OpenRouter-free");
    }
    @Override
    public void init(JadxPluginContext context) {
        JadxGuiContext gui = context.getGuiContext();
        if (gui == null) return; // GHA headless JADX retains deterministic CLI
        gui.addPopupMenuAction("AAR Analyze With Qualified Actor (experimental)",
            ref -> true, null, ref -> {
                final String source;
                try {
                    JavaNode node=context.getDecompiler().getJavaNodeByRef(ref);
                    if (node == null || node.getTopParentClass() == null) {
                        throw new IllegalArgumentException("No selected class code");
                    }
                    source=node.getTopParentClass().getCode();
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null,
                        "Unable to obtain selected decompiled source. No inference requested.");
                    return;
                }
                SwingUtilities.invokeLater(() -> new ActorAssistPanel(source).setVisible(true));
            });
    }
}
