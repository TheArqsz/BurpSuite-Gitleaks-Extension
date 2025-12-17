package com.arqsz.burpgitleaks.ui;

import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.Window;
import java.awt.geom.RoundRectangle2D;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.border.EmptyBorder;

public class Toast extends JDialog {

    public enum MessageType {
        SUCCESS(new Color(34, 139, 34)),
        ERROR(new Color(178, 34, 34)),
        INFO(new Color(70, 130, 180));

        private final Color color;

        MessageType(Color color) {
            this.color = color;
        }

        public Color getColor() {
            return color;
        }
    }

    private static final List<Toast> activeToasts = new ArrayList<>();

    private Toast(Window owner, String message, MessageType type) {
        super(owner);
        setUndecorated(true);
        setAlwaysOnTop(true);
        setFocusableWindowState(false);
        setBackground(new Color(0, 0, 0, 0));

        JLabel label = new JLabel(message);
        label.setForeground(Color.WHITE);
        label.setFont(new Font("SansSerif", Font.BOLD, 12));
        label.setBorder(new EmptyBorder(10, 20, 10, 20));

        JPanel content = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g.create();
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2d.setColor(type.getColor());
                g2d.fill(new RoundRectangle2D.Float(0, 0, getWidth(), getHeight(), 15, 15));
                g2d.dispose();
            }
        };

        content.setOpaque(false);
        content.add(label);

        setContentPane(content);
        pack();
    }

    public static void show(Component parent, String message, MessageType type) {
        Window window;
        if (parent instanceof Window) {
            window = (Window) parent;
        } else {
            window = SwingUtilities.getWindowAncestor(parent);
        }
        show(window, message, type);
    }

    public static void show(Window owner, String message, MessageType type) {
        if (owner == null)
            return;

        SwingUtilities.invokeLater(() -> {
            Toast toast = new Toast(owner, message, type);

            activeToasts.add(toast);
            repositionToasts(owner);

            toast.setVisible(true);

            Timer timer = new Timer(4000, e -> {
                activeToasts.remove(toast);
                toast.dispose();
                repositionToasts(owner);
            });
            timer.setRepeats(false);
            timer.start();
        });
    }

    public static void success(Window owner, String msg) {
        show(owner, msg, MessageType.SUCCESS);
    }

    public static void error(Window owner, String msg) {
        show(owner, msg, MessageType.ERROR);
    }

    public static void info(Window owner, String msg) {
        show(owner, msg, MessageType.INFO);
    }

    public static void success(Component parent, String msg) {
        show(parent, msg, MessageType.SUCCESS);
    }

    public static void error(Component parent, String msg) {
        show(parent, msg, MessageType.ERROR);
    }

    public static void info(Component parent, String msg) {
        show(parent, msg, MessageType.INFO);
    }

    private static void repositionToasts(Window owner) {
        int xBase = owner.getX() + owner.getWidth() - 25;
        int yBase = owner.getY() + owner.getHeight() - 45;
        int gap = 10;

        int currentBottomOffset = 0;

        for (int i = activeToasts.size() - 1; i >= 0; i--) {
            Toast t = activeToasts.get(i);
            if (t.getOwner() != owner)
                continue;

            int toastHeight = t.getHeight();
            t.setLocation(xBase - t.getWidth(), yBase - toastHeight - currentBottomOffset);

            currentBottomOffset += toastHeight + gap;
        }
    }
}