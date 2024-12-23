package org.example.ntoken.api.entity.user;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.*;
import net.minidev.json.annotate.JsonIgnore;
import org.example.ntoken.oauth.entity.RoleType;
import org.example.ntoken.oauth.entity.ProviderType;

import java.time.LocalDateTime;

@Entity
@Builder
@Getter
@Setter
@Table(name = "USER")
@NoArgsConstructor
@AllArgsConstructor
public class User {
    @JsonIgnore
    @Id
    @Column(name = "USER_SEQ")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long userSeq;

    @Column(name = "USER_ID", length = 64, unique = true)
    @NonNull
    @Size(max = 64)
    private String userId;

    @Column(name = "USER_ID", length = 100)
    @NonNull
    @Size(max = 100)
    private String username;

    @JsonIgnore
    @Column(name = "PASSWORD", length = 128)
    @NotNull
    @Size(max = 128)
    private String password;

    @Column(name = "EMAIL", length = 512, unique = true)
    @NotNull
    @Size(max = 512)
    private String email;

    @Column(name = "EMAIL_VERIFIED", length = 1)
    @NotNull
    @Size(min = 1, max = 1)
    private String emailVerified;

    @Column(name = "PROFILE_IMAGE", length = 512)
    @NotNull
    @Size(max = 512)
    private String profileImage;

    @Column(name = "PROVIDER_TYPE", length = 20)
    @Enumerated(EnumType.STRING)
    @NotNull
    private ProviderType providerType;

    @Column(name = "ROLE_TYPE", length = 20)
    @Enumerated(EnumType.STRING)
    @NotNull
    private RoleType roleType;

    @Column(name = "CREATED_AT")
    @NotNull
    private LocalDateTime createdAt;

    public User (
            @NotNull @Size(max = 64) String userId,
            @NotNull @Size(max = 100) String username,
            @NotNull @Size(max = 512) String email,
            @NotNull @Size(max = 1) String emailVerified,
            @NotNull @Size(max = 512) String profileImage,
            @NotNull ProviderType providerType,
            @NotNull RoleType roleType,
            @NotNull LocalDateTime createdAt,
            LocalDateTime now) {
        this.userId = userId;
        this.username = username;
        this.password = "NO_PASS";
        this.email = email != null ? email : "NO_EMAIL";
        this.emailVerified = emailVerified;
        this.profileImage = profileImage != null ? profileImage : "NO_PROFILE_IMAGE";
        this.providerType = providerType;
        this.roleType = roleType;
        this.createdAt = createdAt;
    }

}